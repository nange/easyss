package runner

import (
	"context"
	"errors"
	"fmt"
	"net"
	"runtime"
	"strings"
	"time"

	"github.com/nange/easyss/v3/client/config"
	"github.com/nange/easyss/v3/client/proxy"
	sharedconfig "github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/protocol"
	vpn "github.com/nange/easyss/v3/vpn"
	vpnnode "github.com/nange/easyss/v3/vpn/node"
)

// vpnPaths 是本节点 VPN 状态文件的位置。
//
// 生产路径就是 vpn 包的默认值（与配置、日志同目录的 <exe>/vpn/），这里做成参数
// 只为给测试一个临时目录：密钥文件与 peer.txt 都写在"可执行文件旁边"，测试若用
// 默认值会污染测试二进制所在目录。
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

// vpnStack 是一次会话持有的 VPN 组件。
//
// 它只借用 `route`（注入进 Socks5Server 作为分流面），因此关闭顺序必须是
// "先关代理入口、再关它"——反过来会让在飞的隧道拨号打到一个已关闭的 ClientSet。
// Core.cleanup 保证了这个顺序。
type vpnStack struct {
	face    *vpnnode.PeerFace
	clients *vpnnode.ClientSet
	route   *vpnnode.Route

	// relayOnly 是本次会话**实际生效**的 relay_only：TUN 打开时它会被强制为
	// true（见 startVPN），因此不能只看配置里的值来判断 TUN 是否可用。
	relayOnly bool
	// peers 是配置的对端数量。没有对端时不存在节点间直连，TUN 与
	// relay_only=false 也就没有冲突。
	peers int
}

// startVPNSession 建立本会话的 VPN，返回注入给代理入口的分流面。
//
// 唯一的顺序约束是 relay_only 的进程级开关：tailcat 在创建 WireGuard 引擎时写它
// （见 vpnnode 的 DERPOnly 选项），因此它必须先于任何 tailcat 对象落位——这一点由
// startVPN 内部保证（先算好 relayOnly，再构造对端面与客户端）。
//
// 失败时回收已经建好的部分：调用方只需要把错误交给用户。
func (c *Core) startVPNSession(cfg *config.ClientConfig, handler *proxy.StreamHandler,
	method protocol.Method, timeouts sharedconfig.Timeouts) (proxy.VPNRoute, error) {
	stack, err := startVPN(cfg, timeouts, defaultVPNPaths(), cfg.Local.EnableTun2socks,
		newDERPDialer(handler, method))
	if err != nil {
		return nil, err
	}
	c.vpn = stack
	return stack.route, nil
}

// close 停止对端面并关闭全部隧道客户端。幂等，nil 安全。
//
// 顺序与 PeerFace.Stop 一致：先停止接受新流（对端面），再断开已经建立的隧道
// （客户端）。反过来会让在飞的连接在隧道消失后才被拆除。
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

// startVPN 建立本节点的 VPN 栈并返回它。它由 Run 在创建本地代理入口**之前**调用：
// SOCKS5 服务器要把返回的访问侧注入进自己的分流策略。
//
// tunWanted 表示本会话已经（或即将）启用 TUN。它参与 relay_only 的强制：TUN 与
// 节点间直连不兼容，而且这个强制**必须在这里**完成
// ——tailcat 把 DERPOnly 写进 tailscale 的进程级开关，而 magicsock 是在创建 socket
// 时读它的，等 Server/Client 起来之后再改对已经绑好的 UDP socket 没有作用。
//
// derpDialer 是 tailcat 到 DERP 的拨号器（见 derpdialer.go）：内嵌 DERP 只接待
// 来自服务端回环的连接，因此节点的 DERP 连接必须经 easyss 隧道送出。
//
// 失败时自行回收已经建好的部分，调用方只需要把错误交给用户。
func startVPN(cfg *config.ClientConfig, timeouts sharedconfig.Timeouts, paths vpnPaths, tunWanted bool,
	derpDialer func(ctx context.Context, network, addr string) (net.Conn, error)) (*vpnStack, error) {
	opts, err := vpnOptions(cfg)
	if err != nil {
		return nil, err
	}
	nc, err := vpnnode.NewConfig(opts)
	if err != nil {
		return nil, err
	}

	// TUN 下必须只走中继：没有对端时不存在节点间直连，也就无需强制（用户把
	// relay_only 关掉、只用 TUN 上网是合法的组合，不该被无谓地拖成中继）。
	relayOnly := nc.RelayOnly
	if tunWanted && !relayOnly && len(nc.Peers) > 0 {
		log.Warn("[VPN] tun2socks is enabled and relay_only is false: forcing relay_only on for this session " +
			"(a direct node-to-node path would be captured by the TUN routes and loop back into easyss; " +
			"set vpn.relay_only=true to make this explicit)")
		relayOnly = true
	}
	nc.RelayOnly = relayOnly

	// relay_only 由 tailcat 在创建引擎之前写进 tailscale 的进程级开关（见
	// vpnnode 的 DERPOnly 选项）。
	if relayOnly {
		// 它把服务端变成全部对端流量的带宽瓶颈，因此每次启动都明确打出来，
		// 而不是只在 debug 级别可见。
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
		_ = stack.close()
		return nil, err
	}
	// 地址在启动成功之后才发布：先写文件再启动会让"文件存在但进程起不来"看起来
	// 像一次成功的部署。返回值不在这里记录（它是秘密，见下面的 identity 日志）。
	if _, err := face.PublishAddr(paths.peerAddr); err != nil {
		_ = stack.close()
		return nil, err
	}

	clients, err := vpnnode.NewClientSet(vpnnode.ClientSetOptions{
		KeyPath:    paths.clientKey,
		Peers:      nc.Peers,
		DERPDialer: derpDialer,
		DERPOnly:   relayOnly,
	})
	if err != nil {
		_ = stack.close()
		return nil, err
	}
	stack.clients = clients

	overlay, err := vpnnode.Assign(nc.Overlay, nc.Peers)
	if err != nil {
		_ = stack.close()
		return nil, err
	}
	route, err := vpnnode.NewRoute(vpnnode.RouteOptions{
		Overlay:  overlay,
		Clients:  clients,
		Timeouts: timeouts,
	})
	if err != nil {
		_ = stack.close()
		return nil, err
	}
	stack.route = route

	if len(nc.AllowClients) == 0 {
		// 地址里内嵌 preshared key，因此"拿到地址"就等于"能接进来"；白名单是
		// 唯一的额外硬化手段，没配时必须让它在日志里可见。
		log.Warn("[VPN] vpn.allow_clients is empty: any node that has this node's address can open streams to its peer face " +
			"(fill vpn.allow_clients with the nodekey printed by each peer's -show-vpn-identity)")
	}

	// 两个 key 与一个地址是运维要分发的全部信息，字段名直接写清各自该填到哪里。
	//
	// 这里刻意**不打印地址本身**：它内嵌 preshared key，等价于对端面的接入凭据，
	// 而日志文件是长期留存、经常被整体打包带走的东西。地址只经两条显式路径交给
	// 运维：`-show-vpn-identity` 与下面的 address_file。字段名仍保留 address_file，
	// 使"日志里没有、但文件里有"这件事本身被发现。
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
	// 名字能不能到达静态名钩子取决于**操作系统的解析器**愿不愿意把它交给 DNS，
	// 与钩子本身的正确性无关。
	warnOnSingleLabelPeerNames(runtime.GOOS, nc.Peers)

	return stack, nil
}

// dotlessHostNames 返回 peers 里不含点的 host_name，保持配置顺序。
//
// peers 必须是 vpnnode.NewConfig 归一化之后的视图：那里的 normalizePeers 会去掉
// 一个末尾根点，因此配置里写成 "b." 的名字在这里已经是 "b"——它在 Windows 上同样
// 解析不到，必须一起报出来。
func dotlessHostNames(peers []vpnnode.PeerRef) []string {
	var names []string
	for _, p := range peers {
		if !strings.Contains(p.HostName, ".") {
			names = append(names, p.HostName)
		}
	}
	return names
}

// warnOnSingleLabelPeerNames 在 goos 的解析器不会把单标签（无点）名字交给 DNS 时，
// 为本会话配置的对端名打一条启动警告。
//
// 只有 Windows 命中：它的 DNS 客户端把无点的名字当成 NetBIOS/LLMNR 与后缀搜索列表
// 的输入，从不作为查询发给任何 DNS 服务器（实测 `Resolve-DnsName easyss-mac` 直接
// 返回 ERROR_INVALID_NAME、`ping easyss-mac` 报 "could not find host"，而同名加一个
// 结尾点就能解析）。于是查询根本到不了 TUN 之后的静态名钩子，用户看到的只是"名字
// 解析不了"，日志里连一条 DNS 查询都没有——没有这条警告，这个平台差异只能靠读代码
// 或抓包发现。
//
// goos 由调用方传入而不是在这里读 runtime.GOOS：门控必须能在任意平台上被测试。
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

// vpnCloseTimeout 是等待 VPN 栈拆除完成的上限。拆除必须是有界的：tailcat →
// wireguard-go → magicsock 的关闭路径上有会永久阻塞的分支（magicsock 在 DERP-only
// 模式下重建 UDP socket 时可能把已经 park 的 receive goroutine 遗弃在一个再也不会
// 被关闭的 blockForeverConn 上，于是 wireguard-go 的 Device.Close 永远停在
// netc.stopping.Wait()）。无界拆除的表现就是"托盘图标消失了、进程却永不退出"
// （退出路径），或者"点了切换服务器没有任何反应"（切换路径）——两者都只能强杀
// 进程。超时后放弃等待：卡住的栈要么随进程退出一起消失（退出路径），要么被留在
// 日志里（切换路径，error 里会说明处置方式）。
//
// 它是变量，以便测试把它缩小到毫秒级（与 runCore、rollbackTunRoutes 同一手法）。
var vpnCloseTimeout = 10 * time.Second

// closeVPNStack 是 StopVPN 实际执行的关闭体。它是变量，使测试能注入一个永不返回
// 的关闭过程来验证上面的超时路径，而不必真的构造一个会卡死的 tailcat 引擎。
var closeVPNStack = func(stack *vpnStack) error { return stack.close() }

// StopVPN 停止本节点的 VPN（对端面与全部隧道客户端）。它幂等，且在没有启用 VPN
// 的会话上是空操作。
//
// 关闭在后台 goroutine 上进行，本函数最多等 vpnCloseTimeout：关闭卡死时不能让
// 调用方（退出序列或服务器切换序列）跟着一起卡（见 vpnCloseTimeout 的注释）。
func (c *Core) StopVPN() {
	stack := c.vpn
	c.vpn = nil
	if stack == nil {
		return
	}

	// 关闭体在派发前捕获：goroutine 不再读包级变量（与 runCore、rollbackTunRoutes
	// 的用法一致，也让测试替换注入点时不必与残留 goroutine 竞争）。
	closeFn := closeVPNStack
	done := make(chan error, 1)
	go func() { done <- closeFn(stack) }()

	select {
	case err := <-done:
		if err != nil {
			log.Warn("[VPN] stop", "err", err)
		}
	case <-time.After(vpnCloseTimeout):
		// 放弃等待，但不放弃告知：卡住的引擎仍在占用内存与 DERP 连接。
		// 退出路径上进程马上就结束了，切换路径上它会一直留到用户重启。
		log.Error("[VPN] stop timed out; abandoning this vpn stack",
			"timeout", vpnCloseTimeout,
			"hint", "restart easyss if the vpn or server switching misbehaves")
	}
}

// CheckVPNTunCompat 报告"现在能否为本会话启用 TUN"。
//
// 唯一的冲突是 relay_only=false 下的节点间直连：magicsock 的 UDP socket 会把
// 对端的 disco/WireGuard 报文发进 TUN，而 TUN 又把它们送回 easyss 自己的
// SOCKS5。
//
// 这里刻意**不是**"偷偷把开关置 true 再继续"：tailscale 的开关是在 magicsock
// 建立 socket 时读的，VPN 栈一旦启动就已经绑好了 UDP socket，再改对它们无效
// （tailcat 的 DERPOnly 只在创建引擎时写它）。启动路径上的强制已经在 startVPN
// 里完成——那里还在建 socket 之前，因此是真正生效的；运行期才发现的话只能拒绝，
// 并让用户把 vpn.relay_only 显式打开。
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

// vpnOptions 把客户端配置视图翻译成 vpn 包的原始输入（严格校验在
// vpnnode.NewConfig 里）。
//
// 顺序是刻意的：先确认"有没有中继可通告"，再确认"当前服务端是不是其中之一"。
// 后者是需求 4 的硬门禁——内嵌 DERP 只接待经本服务端隧道送达的连接，声明列表里
// 没有当前服务端时中继永远连不上，因此 VPN 在本会话直接缺席（错误由 runCore 记
// ERROR 并入 StartupWarn），而不是让用户在第一次访问对端时看到超时。
func vpnOptions(cfg *config.ClientConfig) (vpnnode.Options, error) {
	derpAddrs := cfg.VPNDERPAddrs()
	if len(derpAddrs) == 0 {
		return vpnnode.Options{}, errors.New("vpn: cannot derive any DERP host:port this node advertises: " +
			"mark the servers[] entries that run the embedded DERP with \"derp\": true, or set vpn.derp_addr")
	}
	if err := cfg.ValidateDERPServer(); err != nil {
		return vpnnode.Options{}, err
	}
	peers := make([]vpnnode.PeerRef, 0, len(cfg.VPN.Peers))
	for _, p := range cfg.VPN.Peers {
		peers = append(peers, vpnnode.PeerRef{HostName: p.HostName, Address: p.Address, Port: p.Port})
	}
	return vpnnode.Options{
		RelayOnly:    cfg.VPN.RelayOnlyEnabled(),
		PeerPort:     cfg.VPNPeerPort(),
		OverlayCIDR:  cfg.VPN.OverlayCIDR,
		DERPAddrs:    derpAddrs,
		Peers:        peers,
		AllowClients: cfg.VPN.AllowClients,
	}, nil
}

// VPNIdentity 是本机 VPN 身份的可打印形式，供 `-show-vpn-identity` 使用。
//
// 两半是给不同的收件人用的：ClientNodeKey 填到**对端**的 `vpn.allow_clients` 里
// （它是对端面识别访问侧的凭据），TailcatAddr 填到**对端**的
// `vpn.peers[].address` 里（它内嵌了公钥、DERP 位置与 preshared key）。
type VPNIdentity struct {
	// ClientNodeKey 是访问侧 client 公钥（nodekey:... 文本形式）。
	ClientNodeKey string
	// TailcatAddr 是本节点地址（完整展开格式）。AddrErr 非空时为空。
	TailcatAddr string
	// DERPNodes 是地址里内嵌的中继节点（host:port，配置顺序）。它不是秘密，
	// `-show-vpn-identity` 单独列出来是为了让"地址里到底有几个中继"可见：地址
	// 本身是一串不可读的 base64。
	DERPNodes []string
	// AddrErr 是推导本节点地址失败的原因。此时 ClientNodeKey 仍然有效——它不
	// 依赖任何配置，这正是"白名单配不起来"时要先拿到的东西。
	AddrErr error
}

// LoadVPNIdentity 读取（必要时生成）本机的 VPN 身份。
func LoadVPNIdentity(cfg *config.ClientConfig) (*VPNIdentity, error) {
	return loadVPNIdentity(cfg, defaultVPNPaths())
}

func loadVPNIdentity(cfg *config.ClientConfig, paths vpnPaths) (*VPNIdentity, error) {
	key, err := vpn.LoadOrCreateKey(paths.clientKey)
	if err != nil {
		return nil, err
	}
	id := &VPNIdentity{ClientNodeKey: key.Public().String()}

	// 本节点地址是 (身份, DERP 节点列表) 的函数，**与 peers / overlay / peer_port
	// 无关**。这里刻意不经过 vpnnode.NewConfig：运维第一次跑这个命令时 peers 往往
	// 还是空的（他们正需要先拿到地址才能去填对端），若因为 peer 校验失败就报"地址
	// 不可用"，这个命令在最需要它的场景下恰好不可用。
	//
	// 同理也不在这里做"当前服务端必须在列表里"的门禁：那是 VPN 能否工作的判断
	// （见 vpnOptions），而这个命令要能用来排障——它把该问题作为一行 warning 打给
	// 用户（见 cmd/easyss 的 printVPNIdentity）。
	derpAddrs := cfg.VPNDERPAddrs()
	if len(derpAddrs) == 0 {
		id.AddrErr = errors.New("cannot derive any DERP host:port this node advertises: " +
			"mark the servers[] entries that run the embedded DERP with \"derp\": true, or set vpn.derp_addr")
		return id, nil
	}
	region, err := vpn.BuildRegion(derpAddrs...)
	if err != nil {
		id.AddrErr = fmt.Errorf("vpn.derp_addr: %w", err)
		return id, nil
	}
	identity, err := vpnnode.LoadOrCreateNodeIdentity(paths.nodeIdentity)
	if err != nil {
		return nil, err
	}
	addr := identity.Address(region)
	// 这是运维复制地址之前的最后一道关口：一份短格式地址会让每个对端都去拉官方
	// DERPMap。
	if err := vpnnode.AssertFullAddr(addr); err != nil {
		id.AddrErr = fmt.Errorf("the node address would not be usable by peers: %w", err)
		return id, nil
	}
	id.TailcatAddr = addr
	id.DERPNodes = derpAddrs
	return id, nil
}
