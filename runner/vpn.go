package runner

import (
	"context"
	"errors"
	"fmt"

	"github.com/nange/easyss/v3/client/config"
	sharedconfig "github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/log"
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

	// bypass 计算 TUN 会话必须绕行的 DERP 主机 IP 并集（见 docs/vpn-design.md 8.2）。
	bypass *vpnnode.Bypass

	// relayOnly 是本次会话**实际生效**的 relay_only：TUN 打开时它会被强制为
	// true（见 startVPN），因此不能只看配置里的值来判断 TUN 是否可用。
	relayOnly bool
	// peers 是配置的对端数量。没有对端时不存在节点间直连，TUN 与
	// relay_only=false 也就没有冲突。
	peers int
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
// 节点间直连不兼容（见 docs/vpn-design.md 8.1），而且这个强制**必须在这里**完成
// ——tailscale 的开关是在 magicsock 建 socket 时读的，等 tailcat Server/Client
// 起来之后再置 true 对已经绑好的 UDP socket 没有作用。
//
// 失败时自行回收已经建好的部分，调用方只需要把错误交给用户。
func startVPN(cfg *config.ClientConfig, timeouts sharedconfig.Timeouts, paths vpnPaths, tunWanted bool) (*vpnStack, error) {
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
			"set vpn.relay_only=true to make this explicit, see docs/vpn-design.md 8.1)")
		relayOnly = true
	}
	nc.RelayOnly = relayOnly

	// relay_only 是进程级开关，必须在任何 tailcat Client/Server 启动之前设置
	// （见 vpnnode.ApplyRelayOnly 的三条约束）。
	vpnnode.ApplyRelayOnly(relayOnly)
	if relayOnly {
		// 这是 tailscale 的调试开关，且它把服务端变成全部对端流量的带宽瓶颈，
		// 因此每次启动都明确打出来，而不是只在 debug 级别可见。
		log.Warn("[VPN] relay_only is on: every peer connection is forced through the DERP relay of the easyss server "+
			"(relies on the tailscale debug knob "+vpnnode.RelayOnlyEnvKnob+", pinned by the tailscale version in go.mod)",
			"derp_addr", nc.DERPAddr)
	} else {
		log.Info("[VPN] relay_only is off: nodes may establish direct connections to each other", "derp_addr", nc.DERPAddr)
	}

	region, err := vpn.BuildRegion(nc.DERPAddr)
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
	})
	if err != nil {
		return nil, err
	}

	stack := &vpnStack{
		face:      face,
		bypass:    vpnnode.NewBypass(vpnnode.BypassOptions{LocalDERPAddr: nc.DERPAddr, Peers: nc.Peers}),
		relayOnly: relayOnly,
		peers:     len(nc.Peers),
	}
	if err := face.Start(context.Background()); err != nil {
		_ = stack.close()
		return nil, err
	}
	// 地址在启动成功之后才发布：先写文件再启动会让"文件存在但进程起不来"看起来
	// 像一次成功的部署。
	addr, err := face.PublishAddr(paths.peerAddr)
	if err != nil {
		_ = stack.close()
		return nil, err
	}

	clients, err := vpnnode.NewClientSet(vpnnode.ClientSetOptions{
		KeyPath: paths.clientKey,
		Peers:   nc.Peers,
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

	// 两个 key 与一个地址是运维要分发的全部信息，字段名直接写清各自该填到哪里。
	log.Info("[VPN] node identity ready",
		"address", addr, // 对端的 vpn.peers[].address
		"address_file", paths.peerAddr,
		"client_nodekey", clients.ClientKey().String(), // 对端的 vpn.allow_clients
		"peer_port", nc.PeerPort,
		"relay_only", relayOnly,
		"peers", len(nc.Peers))
	for _, ref := range overlay.Peers() {
		ip, ok := overlay.Addr(ref.HostName)
		if !ok {
			continue
		}
		log.Info("[VPN] peer", "host_name", ref.HostName, "overlay_ip", ip.String(), "port", ref.Port)
	}

	return stack, nil
}

// StopVPN 停止本节点的 VPN（对端面与全部隧道客户端）。它幂等，且在没有启用 VPN
// 的会话上是空操作。
func (c *Core) StopVPN() {
	stack := c.vpn
	c.vpn = nil
	if stack == nil {
		return
	}
	if err := stack.close(); err != nil {
		log.Warn("[VPN] stop", "err", err)
	}
}

// VPNBypassIPs 返回 TUN 会话必须绕行物理网关的 DERP 主机 IPv4 并集（见
// docs/vpn-design.md 8.2）。没有启用 VPN 时返回 nil。
//
// 本地标记的 S 复用的是服务端域名预解析的结果（Core.publishServerIPs）：那份地址
// 是隧道拨号实际使用的权威答案，此刻再做一次解析既没必要，也可能撞上"TUN 路由即将
// 安装、DNS 还没有可用出口"的窗口。
func (c *Core) VPNBypassIPs(ctx context.Context) []string {
	if c == nil || c.vpn == nil || c.vpn.bypass == nil {
		return nil
	}
	addrs := c.vpn.bypass.IPs(ctx, c.publishServerIPs())
	if len(addrs) == 0 {
		return nil
	}
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, a.String())
	}
	return out
}

// CheckVPNTunCompat 报告"现在能否为本会话启用 TUN"。
//
// 唯一的冲突是 relay_only=false 下的节点间直连：magicsock 的 UDP socket 会把
// 对端的 disco/WireGuard 报文发进 TUN，而 TUN 又把它们送回 easyss 自己的
// SOCKS5（见 docs/vpn-design.md 8.1）。
//
// 这里刻意**不是**"偷偷把开关置 true 再继续"：tailscale 的开关是在 magicsock
// 建立 socket 时读的，VPN 栈一旦启动就已经绑好了 UDP socket，再改对它们无效
// （见 vpnnode.ApplyRelayOnly）。启动路径上的强制已经在 startVPN 里完成——那里
// 还在建 socket 之前，因此是真正生效的；运行期才发现的话只能拒绝，并让用户把
// vpn.relay_only 显式打开。
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
func vpnOptions(cfg *config.ClientConfig) (vpnnode.Options, error) {
	derpAddr := cfg.VPNDERPAddr()
	if derpAddr == "" {
		return vpnnode.Options{}, errors.New("vpn: cannot derive the DERP host:port this node advertises: " +
			"set vpn.derp_addr, or make sure servers[] has an entry with address/port")
	}
	peers := make([]vpnnode.PeerRef, 0, len(cfg.VPN.Peers))
	for _, p := range cfg.VPN.Peers {
		peers = append(peers, vpnnode.PeerRef{HostName: p.HostName, Address: p.Address, Port: p.Port})
	}
	return vpnnode.Options{
		RelayOnly:    cfg.VPN.RelayOnlyEnabled(),
		PeerPort:     cfg.VPNPeerPort(),
		OverlayCIDR:  cfg.VPN.OverlayCIDR,
		DERPAddr:     derpAddr,
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

	// 本节点地址是 (身份, derp_addr) 的函数，**与 peers / overlay / peer_port 无关**。
	// 这里刻意不经过 vpnnode.NewConfig：运维第一次跑这个命令时 peers 往往还是空的
	// （他们正需要先拿到地址才能去填对端），若因为 peer 校验失败就报"地址不可用"，
	// 这个命令在最需要它的场景下恰好不可用。
	derpAddr := cfg.VPNDERPAddr()
	if derpAddr == "" {
		id.AddrErr = errors.New("cannot derive the DERP host:port this node advertises: " +
			"set vpn.derp_addr, or make sure servers[] has an entry with address/port")
		return id, nil
	}
	region, err := vpn.BuildRegion(derpAddr)
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
	// DERPMap（见 4.7）。
	if err := vpnnode.AssertFullAddr(addr); err != nil {
		id.AddrErr = fmt.Errorf("the node address would not be usable by peers: %w", err)
		return id, nil
	}
	id.TailcatAddr = addr
	return id, nil
}
