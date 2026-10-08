package vpn

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"sync"
	"time"

	"tailscale.com/derp"
	"tailscale.com/derp/derphttp"
	"tailscale.com/derp/derpserver"
	"tailscale.com/net/netmon"
	"tailscale.com/net/netx"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"

	sharedconfig "github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/log"
)

// 本文件实现"同一 region 下多个内嵌 DERP 之间的 mesh"——数据面的一跳转发。
//
// 上游的 derpserver 已经具备全部机制：mesh 同伴（握手时带正确的 MeshKey）可以订阅
// 客户端的上下线（PeerPresent/PeerGone），并代替其他客户端转发数据包
// （ForwardPacket，源公钥保持不变）。缺的只是"谁来当这个 mesh 客户端"：每个中继
// 都要主动连上同 region 的其他中继，把自己看到的那部分客户端名单交给对方。
//
// 三个约束决定了这里的形状：
//
//   - **必须经 easyss 隧道**：内嵌 DERP 只接待回环来源（见 NewDERPMount），而对端
//     的公网 host:port 前面站着伪装页面。因此每条 mesh 连接都交给调用方提供的
//     拨号器（生产上是 nextproxy → 本机 easyss-headless 的 SOCKS5 → 对端服务端），
//     而服务端在握手阶段把"目标就是我的 derp_addr"改拨回环后，它看到的来源正是
//     回环。直连（不经隧道）在协议上不可能成功，所以 Dial 是必填项。
//   - **只能连到对端自己的服务端**：localDERP 是完全匹配，落到别台服务端会被当成
//     普通代理请求直连出去。TLS 证书校验（SNI = 对端 derp_addr 的 host）是这条
//     约束的守门人；连到本机自己的中继则由下面的"首连观测"报出来。
//   - **一跳、不跨 region**：只与 derp_addr 明确列在 mesh_peers 里的对端互联，
//     derpserver 也不会二次转发已经转发过的包。
type MeshPeer struct {
	// Addr 是对端自己的 server.vpn.derp_addr（host:port）。它同时是 TLS SNI 与
	// 请求路径的 host，因此必须与对端的配置逐字一致（比较在配置层完成）。
	Addr string

	// Dial 建立到 Addr 的 TCP 连接，必填：生产上是"经 SOCKS5 → easyss 隧道"，
	// 测试里是直连。签名与 netx.DialFunc 一致。
	Dial netx.DialFunc

	// TLSConfig 可选：对端使用私有/自签证书时用来提供根证书；nil 表示系统根证书
	// （certmagic 的 Let's Encrypt 证书就是这种情形）。
	TLSConfig *tls.Config
}

// MeshOptions 是构造 Mesh 的输入。
type MeshOptions struct {
	// MeshKey 是同一 region 内共享的预共享密钥（明文口令或 64 位 hex，见
	// sharedconfig.ParseVPNMeshKey）。它只交给 derpserver 与 mesh 客户端，绝不写日志。
	MeshKey string

	// Peers 是要互联的其他中继。空列表表示不互联（这不是错误：单节点 region 不需要
	// mesh），但一旦给出就必须完整——只连一部分对端会让数据包在缺失的那一跳上被丢弃。
	Peers []MeshPeer

	// Logf 是第三方库（derphttp）的日志出口，nil 表示 vpn.Logf。
	Logf logger.Logf
}

// Mesh 是一组 mesh 客户端：每个对端一个 derphttp 客户端与一个常驻的订阅循环。
type Mesh struct {
	srv  *derpserver.Server
	logf logger.Logf

	meshKey string // 已归一化的 64 位 hex
	peers   []*meshPeerState

	mu      sync.Mutex
	started bool
	closed  bool
	cancel  context.CancelFunc
	wg      sync.WaitGroup
}

// meshPeerState 是一个对端的运行期状态。
type meshPeerState struct {
	addr string
	opts MeshPeer

	// dc 在 Start 里创建（NewMesh 保持"纯校验、零副作用"）。
	dc *derphttp.Client

	// errOnce 让"这个对端不可用"只报一次警告：上游循环每 5 秒重试一次，逐次告警
	// 会把日志刷满，而故障原因（密钥不一致、代理落错节点、对端没开 mesh）通常不会
	// 自己变化。
	errOnce sync.Once
}

const (
	// meshFirstConnectPollInterval 是"首连观测"的轮询间隔。derphttp 没有"连接成功"
	// 的回调，而这个观测（连上了谁、是不是自己）对排障很重要，因此按固定间隔读一次
	// 原子的公钥快照。
	meshFirstConnectPollInterval = 500 * time.Millisecond

	// meshCloseTimeout 是等待订阅循环退出的上限。与 runner 的 VPN 拆除一致：上游的
	// 关闭链上存在会永久阻塞的分支，退出路径不能被它拖住（超时只告警，不阻塞）。
	meshCloseTimeout = 5 * time.Second
)

// NewMesh 校验 mesh 配置并返回一个未启动的 Mesh。
//
// 它不做任何 I/O：创建客户端、设置 mesh key、拉起订阅循环都在 Start 里，因此一个
// 从未启动的 Mesh 不需要任何清理。
func NewMesh(derpSrv *DERPServer, opts MeshOptions) (*Mesh, error) {
	if derpSrv == nil || derpSrv.srv == nil {
		return nil, errors.New("vpn: mesh requires the embedded DERP server")
	}
	if len(opts.Peers) == 0 {
		return nil, errors.New("vpn: mesh requires at least one peer relay")
	}
	meshKey, err := sharedconfig.ParseVPNMeshKey(opts.MeshKey)
	if err != nil {
		return nil, fmt.Errorf("vpn: mesh key: %w", err)
	}
	logf := opts.Logf
	if logf == nil {
		logf = Logf
	}

	seen := make(map[string]struct{}, len(opts.Peers))
	peers := make([]*meshPeerState, 0, len(opts.Peers))
	for i, p := range opts.Peers {
		canonical, err := sharedconfig.CanonicalDERPAddr(p.Addr)
		if err != nil {
			return nil, fmt.Errorf("vpn: mesh peer %d: %w", i, err)
		}
		if p.Dial == nil {
			return nil, fmt.Errorf("vpn: mesh peer %s has no dialer: the embedded DERP only accepts connections that "+
				"arrive through an easyss tunnel, so a dialer (usually a SOCKS5 proxy) is required", p.Addr)
		}
		if _, dup := seen[canonical]; dup {
			return nil, fmt.Errorf("vpn: mesh peer %s is listed twice", p.Addr)
		}
		seen[canonical] = struct{}{}
		peers = append(peers, &meshPeerState{addr: p.Addr, opts: p})
	}

	return &Mesh{
		srv:     derpSrv.srv,
		logf:    logf,
		meshKey: meshKey,
		peers:   peers,
	}, nil
}

// Start 设置 mesh key 并为每个对端起一个订阅循环。它必须在 DERP 中继开始服务之前
// 调用（derpserver 要求 SetMeshKey 早于服务），这也是 server.Start 的顺序。
//
// ctx 只约束订阅循环的生命周期；Close 会同时取消 ctx 并关闭客户端（上游文档：
// 两者都做才能让循环尽快返回）。
func (m *Mesh) Start(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return errors.New("vpn: mesh is closed")
	}
	if m.started {
		return errors.New("vpn: mesh is already started")
	}
	if err := m.srv.SetMeshKey(m.meshKey); err != nil {
		return fmt.Errorf("vpn: set the DERP mesh key: %w", err)
	}

	permitted, err := key.ParseDERPMesh(m.meshKey)
	if err != nil {
		// ParseVPNMeshKey 已经保证是 64 位 hex，这里只是不让签名漂移变成静默失效。
		return fmt.Errorf("vpn: parse the DERP mesh key: %w", err)
	}

	ctx, cancel := context.WithCancel(ctx)
	m.cancel = cancel
	for _, p := range m.peers {
		dc, err := derphttp.NewClient(m.srv.PrivateKey(), "https://"+p.addr+"/derp",
			logger.WithPrefix(m.logf, "mesh("+p.addr+"): "), netmon.NewStatic())
		if err != nil {
			cancel()
			return fmt.Errorf("vpn: mesh client for %s: %w", p.addr, err)
		}
		dc.MeshKey = permitted
		dc.WatchConnectionChanges = true
		dc.AppName = meshAppName
		dc.TLSConfig = p.opts.TLSConfig
		dc.SetDialer(p.opts.Dial)
		p.dc = dc
	}
	m.started = true

	for _, p := range m.peers {
		m.wg.Add(1)
		go m.watch(ctx, p)
	}

	addrs := make([]string, 0, len(m.peers))
	for _, p := range m.peers {
		addrs = append(addrs, p.addr)
	}
	// mesh_key 本身绝不进日志：它是"被当成可信中继"的凭据。
	log.Info("[VPN] derp mesh started", "peers", addrs, "relay_key", m.srv.PublicKey().ShortString())
	return nil
}

// watch 是一个对端的订阅循环。它对端的客户端必须已经创建（见 Start）。
func (m *Mesh) watch(ctx context.Context, p *meshPeerState) {
	defer m.wg.Done()

	// 首连观测与订阅循环并行：它只读原子的公钥快照，用来把"连上了谁"和"是不是连到
	// 了自己"变成一行日志——否则代理落错节点时用户只能看到一条 TLS 错误。
	go m.watchFirstConnect(ctx, p)

	p.dc.RunWatchConnectionLoop(ctx, m.srv.PublicKey(), m.logf,
		func(msg derp.PeerPresentMessage) { m.srv.AddPacketForwarder(msg.Key, p.dc) },
		func(msg derp.PeerGoneMessage) { m.srv.RemovePacketForwarder(msg.Peer, p.dc) },
		func(err error) {
			// 关闭时循环必然会报一次 "client closed"：那是我们自己关的，不是故障，
			// 不能以 WARN 形式出现在退出路径上。
			if m.isClosed() || errors.Is(err, derphttp.ErrClientClosed) {
				log.Debug("[VPN] derp mesh peer stopped", "peer", p.addr, "err", err)
				return
			}
			p.errOnce.Do(func() {
				log.Warn("[VPN] derp mesh peer is not usable: packets to clients attached to it will be dropped "+
					"(check that both relays share server.vpn.mesh_key and that this peer's proxy really tunnels to it)",
					"peer", p.addr, "err", err)
			})
			log.Debug("[VPN] derp mesh peer error", "peer", p.addr, "err", err)
		})
}

// meshAppName 是 mesh 客户端对 DERP 服务端通告的应用名（纯统计/排障用途；对端
// disallow_app_names 对 mesh 同伴本来就不生效）。
const meshAppName = "easyss-derp-mesh"

// watchFirstConnect 在对端首次连上时打一行日志：连到本机自己的中继（说明代理没有
// 把连接送进对端的隧道）是警告，其余是普通信息。
func (m *Mesh) watchFirstConnect(ctx context.Context, p *meshPeerState) {
	ticker := time.NewTicker(meshFirstConnectPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			got := p.dc.ServerPublicKey()
			if got.IsZero() {
				continue
			}
			if got == m.srv.PublicKey() {
				log.Warn("[VPN] derp mesh peer reached this node's own relay instead of the peer: "+
					"the proxy configured for it is not tunnelling to that peer (check that its easyss client uses the peer as its server)",
					"peer", p.addr)
				return
			}
			log.Info("[VPN] derp mesh peer connected", "peer", p.addr, "relay_key", got.ShortString())
			return
		}
	}
}

// isClosed 报告 Close 是否已经开始。
func (m *Mesh) isClosed() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.closed
}

// Close 取消订阅循环并关闭全部 mesh 客户端。幂等，nil 安全。
//
// 等待是有界的（见 meshCloseTimeout）：退出路径上不能被上游的关闭链拖住。
func (m *Mesh) Close() error {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	m.closed = true
	cancel := m.cancel
	started := m.started
	peers := m.peers
	m.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	var errs []error
	for _, p := range peers {
		if p.dc == nil {
			continue
		}
		if err := p.dc.Close(); err != nil {
			errs = append(errs, fmt.Errorf("mesh peer %s: %w", p.addr, err))
		}
	}
	if !started {
		return errors.Join(errs...)
	}

	done := make(chan struct{})
	go func() {
		m.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(meshCloseTimeout):
		log.Warn("[VPN] derp mesh close timed out; abandoning the watch loops",
			"timeout", meshCloseTimeout, "peers", len(peers))
	}
	return errors.Join(errs...)
}
