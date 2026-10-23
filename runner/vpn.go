package runner

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"runtime"
	"strings"
	"time"

	"tailscale.com/types/key"

	clientconfig "github.com/nange/easyss/v3/client/config"
	"github.com/nange/easyss/v3/client/proxy"
	"github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/protocol"
	vpn "github.com/nange/easyss/v3/vpn"
	vpnnode "github.com/nange/easyss/v3/vpn/node"
)

// vpnPaths 是本节点 VPN 状态文件的位置，生产值见 defaultVPNPaths（<exe>/vpn/，与配置、日志同目录）。
// 默认路径在可执行文件旁边，测试必须换成临时目录，否则会污染测试二进制所在目录。
type vpnPaths struct {
	// nodeIdentity 是 tailcat 服务端身份（本节点地址的来源）。
	nodeIdentity string
	// clientKey 是访问侧 client 私钥（对端 allow_clients 的匹配对象）。
	clientKey string
	// peerAddr 是本节点地址的发布文件，供运维复制到各访问侧。
	peerAddr string
}

func defaultVPNPaths() vpnPaths {
	return vpnPaths{
		nodeIdentity: vpn.NodeIdentityPath(),
		clientKey:    vpn.ClientKeyPath(),
		peerAddr:     vpnnode.PeerFacePath(),
	}
}

// vpnStack 是一次会话持有的 VPN 组件；Core 只借用 route（注入 Socks5Server 作为分流面）。
// 关闭必须先停代理入口再停它，否则在飞的隧道拨号会打到已关闭的 ClientSet（顺序由 Core.cleanup 保证）。
type vpnStack struct {
	face    *vpnnode.PeerFace
	clients *vpnnode.ClientSet
	route   *vpnnode.Route

	// relayOnly 是本次会话**实际生效**的 relay_only（TUN 下会被强制为 true，见 startVPN），
	// 判断 TUN 是否可用时不能只看配置值。
	relayOnly bool
	// peers 是配置的对端数量：没有对端就没有节点间直连，TUN 与 relay_only=false 不冲突。
	peers int
}

// startVPNSession 建立本会话的 VPN，返回注入给代理入口的分流面。
// relay_only 必须先于任何 tailcat 对象落位（tailcat 在创建 WireGuard 引擎时写进程级开关，
// 见 vpnnode 的 DERPOnly），顺序由 startVPN 内部保证；失败时它自行回收已建好的部分。
func (c *Core) startVPNSession(cfg *clientconfig.ClientConfig, handler *proxy.StreamHandler,
	method protocol.Method, timeouts config.Timeouts) (proxy.VPNRoute, error) {
	stack, err := startVPN(cfg, timeouts, defaultVPNPaths(), cfg.Local.EnableTun2socks,
		newDERPDialer(handler, method))
	if err != nil {
		return nil, err
	}
	c.vpn = stack
	return stack.route, nil
}

// close 停止对端面并关闭全部隧道客户端，幂等且 nil 安全。
// 必须先停对端面（不再接受新流）再关客户端，否则在飞连接会在隧道消失后才被拆除。
func (s *vpnStack) close() error {
	if s == nil {
		return nil
	}
	var err error
	if s.face != nil {
		err = s.face.Stop()
	}
	if s.clients != nil {
		if cerr := s.clients.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}
	return err
}

// startVPN 建立本节点的 VPN 栈，必须由 Run 在创建本地代理入口之前调用（SOCKS5 要把返回的 route 注入分流策略）。
// relay_only 的强制只能在这里做：它落到 tailscale 的进程级开关，而 tailcat 的 Client 引擎在首次拨号时才创建，
// 运行期再改会同时影响同进程内其它引擎且对已绑定 socket 无效；derpDialer 让 DERP 连接经 easyss 隧道送出。
func startVPN(cfg *clientconfig.ClientConfig, timeouts config.Timeouts, paths vpnPaths, tunWanted bool,
	derpDialer func(ctx context.Context, network, addr string) (net.Conn, error)) (*vpnStack, error) {
	opts, err := vpnOptions(cfg)
	if err != nil {
		return nil, err
	}
	nc, err := vpnnode.NewConfig(opts)
	if err != nil {
		return nil, err
	}

	// TUN 下必须只走中继；没有对端时不存在节点间直连，无需强制。
	relayOnly := nc.RelayOnly
	if tunWanted && !relayOnly && len(nc.Peers) > 0 {
		log.Warn("[VPN] tun2socks is enabled and relay_only is false: forcing relay_only on for this session " +
			"(a direct node-to-node path would be captured by the TUN routes and loop back into easyss; " +
			"set vpn.relay_only=true to make this explicit)")
		relayOnly = true
	}
	nc.RelayOnly = relayOnly

	if relayOnly {
		log.Warn("[VPN] relay_only is on: every peer connection is forced through the DERP relay of the easyss server",
			"derp_addrs", strings.Join(nc.DERPAddrs, ", "))
	} else {
		log.Info("[VPN] relay_only is off: nodes may establish direct connections to each other",
			"derp_addrs", strings.Join(nc.DERPAddrs, ", "))
	}

	region, err := vpn.BuildRegion(nc.DERPAddrs...)
	if err != nil {
		return nil, err
	}
	identity, err := vpnnode.LoadOrCreateNodeIdentity(paths.nodeIdentity)
	if err != nil {
		return nil, err
	}
	face, err := vpnnode.NewPeerFace(vpnnode.PeerFaceOptions{
		Identity:     identity,
		Region:       region,
		PeerPort:     nc.PeerPort,
		AllowClients: nc.AllowClients,
		Timeouts:     timeouts,
		DERPDialer:   derpDialer,
		DERPOnly:     relayOnly,
	})
	if err != nil {
		return nil, err
	}

	stack := &vpnStack{
		face:      face,
		relayOnly: relayOnly,
		peers:     len(nc.Peers),
	}
	if err := face.Start(context.Background()); err != nil {
		closeVPNStackWithin(stack)
		return nil, err
	}
	// 地址必须在启动成功之后才发布：先写文件再启动会让"文件存在但进程起不来"看起来像部署成功。
	if _, err := face.PublishAddr(paths.peerAddr); err != nil {
		closeVPNStackWithin(stack)
		return nil, err
	}

	clients, err := vpnnode.NewClientSet(vpnnode.ClientSetOptions{
		KeyPath:    paths.clientKey,
		Peers:      nc.Peers,
		DERPDialer: derpDialer,
		DERPOnly:   relayOnly,
	})
	if err != nil {
		closeVPNStackWithin(stack)
		return nil, err
	}
	stack.clients = clients

	overlay, err := vpnnode.Assign(nc.Overlay, nc.Peers)
	if err != nil {
		closeVPNStackWithin(stack)
		return nil, err
	}
	route, err := vpnnode.NewRoute(vpnnode.RouteOptions{
		Overlay:  overlay,
		Clients:  clients,
		Timeouts: timeouts,
	})
	if err != nil {
		closeVPNStackWithin(stack)
		return nil, err
	}
	stack.route = route

	if len(nc.AllowClients) == 0 {
		// 地址里内嵌 preshared key，因此"拿到地址"就等于"能接进来"；白名单是
		// 唯一的额外硬化手段，没配时必须让它在日志里可见。
		log.Warn("[VPN] vpn.allow_clients is empty: any node that has this node's address can open streams to its peer face " +
			"(fill vpn.allow_clients with the nodekey printed by each peer's \"easyss vpn identity\")")
	}

	// 地址内嵌 preshared key（等价于对端面接入凭据），绝不进日志：只经 `easyss vpn identity`
	// 与 address_file 交付，字段名保留 address_file 让"日志里没有、文件里有"可被发现。
	log.Info("[VPN] node identity ready",
		"address_file", paths.peerAddr, // 对端的 vpn.peers[].address（地址本身是秘密，不写日志）
		"client_nodekey", clients.ClientKey().String(), // 对端的 vpn.allow_clients
		"peer_port", nc.PeerPort,
		"relay_only", relayOnly,
		"derp_addrs", strings.Join(nc.DERPAddrs, ", "), // 中继是哪些主机（非秘密），不含地址令牌
		"peers", len(nc.Peers))
	for _, ref := range overlay.Peers() {
		ip, ok := overlay.Addr(ref.HostName)
		if !ok {
			continue
		}
		log.Info("[VPN] peer", "host_name", ref.HostName, "overlay_ip", ip.String(), "port", ref.Port)
	}
	// 名字能否到达静态名钩子取决于操作系统的解析器是否把它交给 DNS，与钩子本身无关。
	warnOnSingleLabelPeerNames(runtime.GOOS, nc.Peers)

	return stack, nil
}

// dotlessHostNames 返回 peers 里不含点的 host_name，保持配置顺序。
// peers 必须是 vpnnode.NewConfig 归一化后的视图：normalizePeers 去掉一个末尾根点，写成 "b." 的
// 名字在这里已是 "b"，Windows 上同样解析不到，必须一起报出来。
func dotlessHostNames(peers []vpnnode.PeerRef) []string {
	var names []string
	for _, p := range peers {
		if !strings.Contains(p.HostName, ".") {
			names = append(names, p.HostName)
		}
	}
	return names
}

// warnOnSingleLabelPeerNames 在 goos 的解析器不会把单标签（无点）名字交给 DNS 时打一条启动
// 警告：Windows 把它当作 NetBIOS/LLMNR 与后缀搜索列表的输入，查询到不了 TUN 之后的静态名钩子。
// goos 由调用方传入以便任意平台可测；平台实测见 docs/architecture.md 要点 19。
func warnOnSingleLabelPeerNames(goos string, peers []vpnnode.PeerRef) {
	if goos != "windows" {
		return
	}
	names := dotlessHostNames(peers)
	if len(names) == 0 {
		return
	}
	log.Warn("[VPN] peer names without a dot cannot be resolved on Windows: its resolver does not send "+
		"single-label names to any DNS server, so the query never reaches the VPN's static DNS answer; "+
		"give the peer a dotted host_name (e.g. \"easyss-mac.vpn\"), type the name with a trailing dot "+
		"(\"easyss-mac.\"), or map the overlay IP in the hosts file",
		"host_names", strings.Join(names, ", "))
}

// vpnCloseTimeout 是等待 VPN 栈拆除完成的上限：tailcat → wireguard-go → magicsock 的关闭路径上
// 有会永久阻塞的分支（DERP-only 下重建 UDP socket 时可能遗弃 receive goroutine），无界拆除的表现
// 是进程永不退出，或切换服务器无反应。它是变量，供测试缩小到毫秒级。
var vpnCloseTimeout = 10 * time.Second

// closeVPNStack 是 vpnStack 实际执行的关闭体；它是变量，供测试注入永不返回的关闭过程以验证超时路径。
var closeVPNStack = func(stack *vpnStack) error { return stack.close() }

// closeVPNStackWithin 在 vpnCloseTimeout 内关闭 stack。关闭链可能永久阻塞（见上面的说明），
// 因此启动失败的回收与退出/切换共用同一层兜底：调用方永远能往下走。
func closeVPNStackWithin(stack *vpnStack) {
	// 关闭体在派发前捕获：goroutine 不读包级变量，测试替换注入点时不必与残留 goroutine 竞争。
	closeFn := closeVPNStack
	done := make(chan error, 1)
	go func() { done <- closeFn(stack) }()

	select {
	case err := <-done:
		if err != nil {
			log.Warn("[VPN] close stack", "err", err)
		}
	case <-time.After(vpnCloseTimeout):
		// 放弃等待但不放弃告知：卡住的引擎仍占着内存与 DERP 连接，切换路径上会留到用户重启。
		log.Error("[VPN] close timed out; abandoning this vpn stack",
			"timeout", vpnCloseTimeout,
			"hint", "restart easyss if the vpn or server switching misbehaves")
	}
}

// StopVPN 停止本节点的 VPN（对端面与全部隧道客户端），幂等，未启用 VPN 时是空操作。
// 关闭在后台进行且最多等 vpnCloseTimeout：关闭卡死时不能让退出/切换序列跟着卡住。
func (c *Core) StopVPN() {
	stack := c.vpn
	c.vpn = nil
	if stack == nil {
		return
	}
	closeVPNStackWithin(stack)
}

// CheckVPNTunCompat 报告当前能否为本会话启用 TUN。唯一冲突是 relay_only=false 下的节点间直连：
// magicsock 的 UDP socket 会把对端报文发进 TUN，TUN 又把它送回 easyss 的 SOCKS5。
// 运行期只能拒绝——进程级开关只在建 socket 时读一次，启动路径的强制已在 startVPN 里完成。
func (c *Core) CheckVPNTunCompat() error {
	if c == nil || c.vpn == nil {
		return nil
	}
	if c.vpn.relayOnly || c.vpn.peers == 0 {
		return nil
	}
	return errors.New("tun2socks requires vpn.relay_only=true: with direct node-to-node connections enabled, " +
		"the peer traffic would be captured by the TUN routes and loop back into easyss; " +
		"set vpn.relay_only to true and restart, or leave system-wide traffic off")
}

// vpnOptions 把客户端配置视图翻译成 vpn 包的原始输入（严格校验在 vpnnode.NewConfig 里）。
// 当前服务端不在声明的 derp 列表里时 VPN 本会话直接缺席：内嵌 DERP 只接待经本服务端隧道送达的
// 连接；cfg 是会话起点的不可变快照，切换序列已在启动新会话之前发布目标下标。
func vpnOptions(cfg *clientconfig.ClientConfig) (vpnnode.Options, error) {
	derpAddrs := cfg.VPNDERPAddrs()
	if len(derpAddrs) == 0 {
		return vpnnode.Options{}, errors.New("vpn: cannot derive any DERP host:port this node advertises: " +
			"mark the servers[] entries that run the embedded DERP with \"derp\": true")
	}
	if err := cfg.ValidateDERPServerAddr(cfg.DefaultServer().HostPort()); err != nil {
		return vpnnode.Options{}, err
	}
	peers := make([]vpnnode.PeerRef, 0, len(cfg.VPN.Peers))
	for _, p := range cfg.VPN.Peers {
		peers = append(peers, vpnnode.PeerRef{HostName: p.HostName, Address: p.Address, Port: p.Port})
	}
	return vpnnode.Options{
		RelayOnly:    cfg.VPN.RelayOnlyEnabled(),
		PeerPort:     cfg.VPNPeerPort(),
		DERPAddrs:    derpAddrs,
		Peers:        peers,
		AllowClients: cfg.VPN.AllowClients,
	}, nil
}

// VPNIdentity 是本机 VPN 身份的可打印形式，供 `easyss vpn identity` 使用。
// 两半的收件人不同：ClientNodeKey 填到对端的 `vpn.allow_clients`，TailcatAddr 填到对端的
// `vpn.peers[].address`（内嵌公钥、DERP 位置与 preshared key）。
type VPNIdentity struct {
	// ClientNodeKey 是访问侧 client 公钥（nodekey:... 文本形式）。
	ClientNodeKey string
	// TailcatAddr 是本节点地址（完整展开格式）。AddrErr 非空时为空。
	TailcatAddr string
	// DERPNodes 是地址里内嵌的中继节点（host:port，配置顺序），不是秘密。
	DERPNodes []string
	// HasNodeIdentity 报告身份文件是否可读。它为 false 时地址必然不可用（AddrErr 给出原因）；
	// 它为 true 时地址仍可能因中继列表推不出来而为空。
	HasNodeIdentity bool
	// AddrErr 是推导本节点地址失败的原因；此时 ClientNodeKey 仍然有效（它不依赖任何配置）。
	AddrErr error
}

// VPNKeyKind 是"重新生成哪一半身份"的位掩码，取值与语义都定义在 vpn 包（见 vpn.KeyKind）。
// 两半的收件人不同：换 node identity 让所有对端的 `vpn.peers[].address` 失效，换 client key
// 让所有对端的 `vpn.allow_clients` 失效（没配白名单时无感）。
type VPNKeyKind = vpn.KeyKind

const (
	// RegenNodeIdentity 重新生成 tailcat 服务端身份（地址因此改变，nodekey 不变）。
	RegenNodeIdentity = vpn.KindNodeIdentity
	// RegenClientKey 重新生成访问侧 client 私钥（nodekey 因此改变，地址不变）。
	RegenClientKey = vpn.KindClientKey
)

// VPNRegenOptions 是 `easyss vpn regen` 的输入。
type VPNRegenOptions struct {
	// Kinds 要重新生成的身份。为零表示调用方没有指定，由命令行层决定"两个都换"。
	Kinds VPNKeyKind
	// DryRun 只预览一份新身份，不写任何文件（落盘后旧身份只剩备份文件可回滚）。密钥是每次
	// 调用现生成的，因此预览值不会与随后真写的身份相同，不能直接分发给对端。
	DryRun bool
}

// VPNRegenResult 是一次重新生成的结果：新身份、被替换掉的旧值、以及动过的文件。
// Old* 三个字段在 DryRun 下是即将被替换的当前值，真写时是替换前的实际内容——对端配置里
// 写的正是它。
type VPNRegenResult struct {
	// Identity 是生成后的身份（DryRun 下只是一份预览，不是将要落盘的字节）。
	Identity *VPNIdentity
	// OldClientNodeKey / OldTailcatAddr 是替换前的身份，不存在时为空。
	OldClientNodeKey string
	OldTailcatAddr   string
	// Backups 是被替换掉的身份文件备份路径（键为文件路径，值为备份路径）。
	Backups map[string]string
	// BackupPaths 与 Backups 同源，仅按"被替换的顺序"排列，供输出稳定遍历。
	BackupPaths []string
	// Replaced 是**实际被替换掉**的那几半身份：DryRun 下一半都没换，回显旧值与提醒更新对端
	// 只对真的换掉的那一半成立，按 Kinds 判定会打印出逐字节没变的"旧值"。
	Replaced VPNKeyKind
	// DryRun 回显输入，使输出不必再区分两种调用。
	DryRun bool
}

// RegenerateVPNIdentity 重新生成本机的 VPN 身份（生产路径：<exe>/vpn/ 下的三份文件）。
// 必须"先推导、后落盘"：算不出地址时要在任何文件被改写之前失败，否则本节点丢掉地址、对端全部失联。
// 换 client key 与换身份是两次独立的文件替换，中途失败可能只写了一半；不做自动回滚，备份文件才是回滚凭据。
func RegenerateVPNIdentity(cfg *clientconfig.ClientConfig, opts VPNRegenOptions) (*VPNRegenResult, error) {
	return regenerateVPNIdentity(cfg, defaultVPNPaths(), opts)
}

func regenerateVPNIdentity(cfg *clientconfig.ClientConfig, paths vpnPaths, opts VPNRegenOptions) (*VPNRegenResult, error) {
	res := &VPNRegenResult{DryRun: opts.DryRun, Backups: map[string]string{}}

	// 旧值按只读路径取出：LoadOrCreate* 会补建缺失的身份文件，而 --dry-run 的契约是
	// 不写任何文件；缺失的那一半在旧值里就是空（对端配置里也还没有它）。
	oldClientKey, err := vpn.LoadKey(paths.clientKey)
	switch {
	case err == nil:
	case errors.Is(err, fs.ErrNotExist):
		oldClientKey = key.NodePrivate{}
	default:
		return nil, err
	}
	oldNodeIdentity, err := vpnnode.LoadNodeIdentity(paths.nodeIdentity)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		// 不换身份时坏文件必须原样报出去；要换身份时它不是致命错误——重新生成正是修复它的方式。
		if opts.Kinds&RegenNodeIdentity == 0 {
			return nil, err
		}
		oldNodeIdentity = nil
	}
	if errors.Is(err, fs.ErrNotExist) {
		oldNodeIdentity = nil
	}

	oldID, err := deriveVPNIdentity(cfg, oldClientKey, oldNodeIdentity)
	if err != nil {
		return nil, err
	}
	res.OldClientNodeKey = oldID.ClientNodeKey
	res.OldTailcatAddr = oldID.TailcatAddr

	// 新身份先生成好，DryRun 与真写共用同一份字节；生成留到写入那一步会让 --dry-run 打印当前身份。
	newClientKey := key.NewNode()
	var newIdentity *vpnnode.NodeIdentity
	if opts.Kinds&RegenNodeIdentity != 0 {
		newIdentity = vpnnode.NewNodeIdentity()
	}

	// 没被换掉的那一半保留当前值参与推导（地址与 nodekey 是两个独立输入），换掉的那一半直接用
	// 新生成的那份，使返回的身份与写进文件的字节同源。缺失时按真写路径的语义补建：真写走
	// LoadOrCreate 落盘，dry-run 只在内存里生成一份（写文件是 --dry-run 明确排除的副作用）。
	clientKey := oldClientKey
	switch {
	case opts.Kinds&RegenClientKey != 0:
		clientKey = newClientKey
	case clientKey.IsZero():
		if opts.DryRun {
			clientKey = newClientKey
		} else if clientKey, err = vpn.LoadOrCreateKey(paths.clientKey); err != nil {
			return nil, err
		}
	}

	nodeIdentity := oldNodeIdentity
	switch {
	case newIdentity != nil:
		nodeIdentity = newIdentity
	case nodeIdentity == nil:
		if opts.DryRun {
			nodeIdentity = vpnnode.NewNodeIdentity()
		} else if nodeIdentity, err = vpnnode.LoadOrCreateNodeIdentity(paths.nodeIdentity); err != nil {
			return nil, err
		}
	}

	id, err := deriveVPNIdentity(cfg, clientKey, nodeIdentity)
	if err != nil {
		return res, err
	}
	if newIdentity != nil && id.AddrErr != nil {
		return res, fmt.Errorf("cannot regenerate the node identity: the node address would not be usable (%w); "+
			"the current identity and its address are unchanged", id.AddrErr)
	}
	res.Identity = id

	if opts.Kinds&RegenClientKey != 0 && !opts.DryRun {
		backup, err := vpn.RegenerateFile(paths.clientKey, "client key", newClientKey.MarshalText)
		if err != nil {
			return res, err
		}
		res.recordBackup(paths.clientKey, backup)
		res.Replaced |= RegenClientKey
	}
	if newIdentity != nil && !opts.DryRun {
		backup, err := vpnnode.RegenerateNodeIdentityFile(paths.nodeIdentity, newIdentity)
		if err != nil {
			return res, err
		}
		res.recordBackup(paths.nodeIdentity, backup)
		res.Replaced |= RegenNodeIdentity
		// 地址文件是运维抄给对端的来源，必须与新身份一致：地址是 (身份, 中继集合) 的纯函数，
		// 不重写就会留着一份内嵌旧 preshared key 的地址，而旧的私钥只剩 .bak。
		if err := vpnnode.WritePeerAddr(paths.peerAddr, id.TailcatAddr); err != nil {
			return res, err
		}
	}
	return res, nil
}

// recordBackup 记录一次文件替换，同时保持两个视图一致。
func (r *VPNRegenResult) recordBackup(path, backup string) {
	if backup == "" {
		return
	}
	r.Backups[path] = backup
	r.BackupPaths = append(r.BackupPaths, path)
}

// LoadVPNIdentity 读取（必要时生成）本机的 VPN 身份。
func LoadVPNIdentity(cfg *clientconfig.ClientConfig) (*VPNIdentity, error) {
	return loadVPNIdentity(cfg, defaultVPNPaths())
}

// loadVPNIdentity 是"读现有身份"的路径：两份密钥都按需生成（第一次跑时本就不存在）。
func loadVPNIdentity(cfg *clientconfig.ClientConfig, paths vpnPaths) (*VPNIdentity, error) {
	clientKey, err := vpn.LoadOrCreateKey(paths.clientKey)
	if err != nil {
		return nil, err
	}
	// 身份文件坏掉时不在这里失败：地址那半带 AddrErr 返回，client nodekey 仍然可用。
	nodeIdentity, nodeIdentityErr := vpnnode.LoadOrCreateNodeIdentityFile(paths.nodeIdentity)
	if nodeIdentityErr != nil {
		nodeIdentity = nil
	}
	return deriveVPNIdentity(cfg, clientKey, nodeIdentity)
}

// deriveVPNIdentity 把 (client key, node identity, 配置) 组合成可打印的身份；nodeIdentity 为 nil
// （文件缺失或损坏）时地址不可用，nodekey 照常返回。地址是 (身份, DERP 节点列表) 的函数，与
// peers/overlay/peer_port 无关，因此不经过 vpnnode.NewConfig、也不做"当前服务端在列表里"的门禁（见 vpnOptions）。
func deriveVPNIdentity(cfg *clientconfig.ClientConfig, clientKey key.NodePrivate, nodeIdentity *vpnnode.NodeIdentity) (*VPNIdentity, error) {
	// 零值 key 表示"没有身份文件"（--dry-run 的只读旧值路径），此时 nodekey 不可打印。
	id := &VPNIdentity{HasNodeIdentity: nodeIdentity != nil}
	if !clientKey.IsZero() {
		id.ClientNodeKey = clientKey.Public().String()
	}

	derpAddrs := cfg.VPNDERPAddrs()
	if len(derpAddrs) == 0 {
		id.AddrErr = errors.New("cannot derive any DERP host:port this node advertises: " +
			"mark the servers[] entries that run the embedded DERP with \"derp\": true")
		return id, nil
	}
	region, err := vpn.BuildRegion(derpAddrs...)
	if err != nil {
		id.AddrErr = fmt.Errorf("the declared DERP relay list: %w", err)
		return id, nil
	}
	if nodeIdentity == nil {
		id.AddrErr = errors.New("cannot read the node identity: " + vpn.RegenHint)
		return id, nil
	}
	addr := nodeIdentity.Address(region)
	// 最后一道关口：短格式地址会让每个对端去拉官方 DERPMap。
	if err := vpnnode.AssertFullAddr(addr); err != nil {
		id.AddrErr = fmt.Errorf("the node address would not be usable by peers: %w", err)
		return id, nil
	}
	id.TailcatAddr = addr
	id.DERPNodes = derpAddrs
	return id, nil
}
