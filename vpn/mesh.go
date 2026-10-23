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

	"github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/log"
)

// mesh 让同 region 的中继互为 derpserver 的 mesh 同伴：订阅对端客户端的上下线，并把包转发
// 一跳。连接必须经调用方的拨号器走 easyss 隧道（内嵌 DERP 只接待回环来源），TLS 校验保证
// 落到对端自己的服务端；只连 mesh_peers 里明确列出的对端。见 docs/architecture.md 要点 19。
type MeshPeer struct {
	// Addr 是对端自己的 DERP 对外地址（domain + listen 端口），同时是 TLS SNI 与请求路径的
	// host，必须与对端配置逐字一致（比较在配置层完成）。
	Addr string

	// Dial 建立到 Addr 的 TCP 连接，必填；生产上经 SOCKS5 → easyss 隧道，签名同 netx.DialFunc。
	Dial netx.DialFunc

	// TLSConfig 可选：对端用私有/自签证书时提供根证书，nil 用系统根证书。
	TLSConfig *tls.Config
}

type MeshOptions struct {
	// MeshKey 是同 region 共享的预共享密钥（口令或 64 位 hex，见 config.ParseVPNMeshKey），
	// 只交给 derpserver 与 mesh 客户端，绝不写日志。
	MeshKey string

	// Peers 是要互联的其他中继：一旦给出就必须完整，只连一部分会让包在被漏掉的那跳丢弃。
	Peers []MeshPeer

	// Logf 是 derphttp 的日志出口，nil 用 vpn.Logf。
	Logf logger.Logf
}

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

type meshPeerState struct {
	addr string
	opts MeshPeer

	// dc 在 Start 里创建：NewMesh 只校验、不做 I/O。
	dc *derphttp.Client

	// errOnce 让"该对端不可用"只告警一次：上游每 5 秒重试，而故障原因通常不会变化。
	errOnce sync.Once
}

const (
	// meshFirstConnectPollInterval 是首连观测的轮询间隔：derphttp 没有连接成功回调，只能定时
	// 读一次原子的公钥快照。
	meshFirstConnectPollInterval = 500 * time.Millisecond

	// meshCloseTimeout 是等待订阅循环退出的上限：上游关闭链有会永久阻塞的分支，超时只告警。
	meshCloseTimeout = 5 * time.Second
)

// NewMesh 只做校验，所有 I/O 都在 Start，因此未启动的 Mesh 无需清理。
func NewMesh(derpSrv *DERPServer, opts MeshOptions) (*Mesh, error) {
	if derpSrv == nil || derpSrv.srv == nil {
		return nil, errors.New("vpn: mesh requires the embedded DERP server")
	}
	if len(opts.Peers) == 0 {
		return nil, errors.New("vpn: mesh requires at least one peer relay")
	}
	meshKey, err := config.ParseVPNMeshKey(opts.MeshKey)
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
		canonical, err := config.CanonicalDERPAddr(p.Addr)
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

// Start 必须在 DERP 中继开始服务之前调用（derpserver 要求 SetMeshKey 早于服务），这也是
// server.Start 的顺序。ctx 只约束订阅循环；Close 同时取消 ctx 与关闭客户端，两者都做才能
// 让循环尽快返回。
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
		// ParseVPNMeshKey 已保证是 64 位 hex；这里不让签名漂移变成静默失效。
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

// watch 是单个对端的订阅循环，调用前该对端的客户端必须已创建（见 Start）。
func (m *Mesh) watch(ctx context.Context, p *meshPeerState) {
	defer m.wg.Done()

	// 首连观测与订阅循环并行：它只读原子的公钥快照，把"连到谁、是不是自己"变成一行日志。
	go m.watchFirstConnect(ctx, p)

	p.dc.RunWatchConnectionLoop(ctx, m.srv.PublicKey(), m.logf,
		func(msg derp.PeerPresentMessage) { m.srv.AddPacketForwarder(msg.Key, p.dc) },
		func(msg derp.PeerGoneMessage) { m.srv.RemovePacketForwarder(msg.Peer, p.dc) },
		func(err error) {
			// 关闭时循环必然报一次 "client closed"：那是自己关的，不能以 WARN 出现在退出路径上。
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

// meshAppName 是 mesh 客户端对 DERP 服务端通告的应用名（统计用；对端的 disallow_app_names
// 本来就不作用于 mesh 同伴）。
const meshAppName = "easyss-derp-mesh"

// watchFirstConnect 在对端首次连上时记一行：连到本机自己的中继是警告，其余是信息。
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

func (m *Mesh) isClosed() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.closed
}

// Close 取消订阅循环并关闭全部客户端，幂等且 nil 安全；等待有界（见 meshCloseTimeout）。
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
