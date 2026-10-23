package vpnnode

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"

	tailcat "github.com/tailscale/tailcat"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"

	"github.com/nange/easyss/v3/client/proxy"
	"github.com/nange/easyss/v3/client/router"
	"github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/stats"

	vpn "github.com/nange/easyss/v3/vpn"
)

// PeerFacePath 返回对端面地址文件（<exe>/vpn/peer.txt）的路径。
// 内容必须是完整展开格式（见 AssertFullAddr）：运维会把它原样抄进访问侧的 vpn.peers[].address。
func PeerFacePath() string { return filepath.Join(vpn.StateDir(), "peer.txt") }

type PeerFaceOptions struct {
	Identity *NodeIdentity
	// Region 是要内嵌进地址的 DERP region（见 BuildRegion）。
	Region *tailcfg.DERPRegion
	// PeerPort 是对端面在隧道内的监听端口（不在宿主上监听）。
	PeerPort int
	// AllowClients 是允许接入的对端 node key；为空表示不限制。
	AllowClients []key.NodePublic
	// Timeouts 提供拨号与空闲超时。
	Timeouts config.Timeouts
	// DERPDialer 是 tailcat 到 DERP 的拨号器（见 runner/derpdialer.go）：内嵌
	// DERP 只接待来自服务端回环的连接，因此这条连接必须由调用方指定怎么走。
	// nil 表示用 tailcat 的默认拨号器（只适用于公开可达的 DERP）。
	DERPDialer func(ctx context.Context, network, addr string) (net.Conn, error)
	// DERPOnly 交给 tailcat 的同名选项：为 true 时不建 UDP socket，节点间没有
	// 直连路径。
	DERPOnly bool
}

// PeerFace 是本节点的对端面：对端经 tailcat 隧道访问本机的服务端口。
// 入站只能靠 tailcat Server（tailcat 客户端不接受入站）；TCP 与 UDP 都在本机
// 终止于只接受字面 loopback 目标的路径，因此不可能成为内网跳板。
type PeerFace struct {
	opts  PeerFaceOptions
	srv   *tailcat.Server
	socks *proxy.Socks5Server
	relay *UDPRelay

	tcpLn net.Listener
	udpLn net.Listener

	stopOnce sync.Once
	stopErr  error
	wg       sync.WaitGroup
}

// NewPeerFace 构造对端面，并在构造期自检地址（见 AssertFullAddr）。
// 必须在 Start 之前拦下不可用的地址：否则问题要到对端第一次访问时才暴露，且看起来像网络故障。
func NewPeerFace(opts PeerFaceOptions) (*PeerFace, error) {
	if opts.Identity == nil {
		return nil, errors.New("vpn: peer face requires a node identity")
	}
	if opts.PeerPort <= 0 || opts.PeerPort > 65535 {
		return nil, fmt.Errorf("vpn: invalid peer port %d", opts.PeerPort)
	}
	if err := vpn.ValidateRegion(opts.Region); err != nil {
		return nil, err
	}

	face := &PeerFace{opts: opts}
	if err := AssertFullAddr(face.TailcatAddr()); err != nil {
		return nil, fmt.Errorf("vpn: the node address is not usable by peers: %w", err)
	}
	return face, nil
}

// TailcatAddr 返回本节点的 tailcat 地址（完整展开格式，可直接给对端使用）。
func (p *PeerFace) TailcatAddr() string {
	return p.opts.Identity.Address(p.opts.Region)
}

// NodeKey 返回本节点对端面的 node 公钥。访问侧的 vpn.allow_clients 里要填的就是
// 这个值（文本形式见 NodeKeyString）。
func (p *PeerFace) NodeKey() key.NodePublic {
	return p.opts.Identity.Public.ServerPublic.NodePublic
}

// Start 启动对端面：tailcat Server 与隧道内的 TCP/UDP 监听器。
// ctx 只约束启动工作（region 已内嵌，不联网）；返回后生命周期交给 Stop。
func (p *PeerFace) Start(ctx context.Context) error {
	if p.srv != nil {
		return errors.New("vpn: peer face already started")
	}

	srv := &tailcat.Server{
		Key:          p.opts.Identity.Private,
		PresharedKey: p.opts.Identity.Public.PresharedKey,
		DERPDialer:   p.opts.DERPDialer,
		DERPOnly:     p.opts.DERPOnly,
		// Region 必须设置（而不是 RegionID）：只有内嵌完整 region，TailcatAddr()
		// 才会产出不需要查询任何 DERPMap 的完整格式地址。
		Region: p.opts.Region,
		Logf:   vpn.Logf,
		// 为空表示不限制；非空时 tailcat 会静默忽略不在名单里的客户端。
		AllowedClients: p.opts.AllowClients,
	}

	port := ":" + strconv.Itoa(p.opts.PeerPort)
	// Listen 会在需要时隐式 Start。TCP 与 UDP 各一个监听器，都在隧道里（宿主上看
	// 不到这些端口），因此与宿主的端口占用互不影响。
	tcpLn, err := srv.Listen(ctx, "tcp", port)
	if err != nil {
		_ = srv.Close()
		return fmt.Errorf("vpn: peer face tcp listen: %w", err)
	}
	udpLn, err := srv.Listen(ctx, "udp", port)
	if err != nil {
		_ = tcpLn.Close()
		_ = srv.Close()
		return fmt.Errorf("vpn: peer face udp listen: %w", err)
	}

	socks, err := proxy.NewSocks5Server(proxy.Socks5Options{
		// 对端面不做任何分流判定：所有目标都判直连，真正的门槛是下面的拨号器。
		Router: router.NewDirectOnly(),
		// 关闭 53 端口拦截：在对端面上 53 只是一个普通服务端口（如
		// systemd-resolved），而不是"按查询域名重新分流"的 DNS。
		DisableDNSIntercept: true,
		// 关闭 UDP ASSOCIATE：对端面的 UDP 走 tailcat 的 UDP listener + 薄中继
		// （见 udprelay.go）。ASSOCIATE 会绑对端没有的 tailcat ULA，必须显式关闭。
		DisableUDPAssociate: true,
		// 唯一的跨节点协议契约：只拨字面 loopback 目标。域名与其他一切目标被拒。
		DirectDialContext: LoopbackDialContext,
		Timeouts:          p.opts.Timeouts,
	})
	if err != nil {
		_ = udpLn.Close()
		_ = tcpLn.Close()
		_ = srv.Close()
		return fmt.Errorf("vpn: peer face socks5: %w", err)
	}

	p.srv = srv
	p.tcpLn = tcpLn
	p.udpLn = udpLn
	p.socks = socks
	p.relay = &UDPRelay{Logf: vpn.Logf}

	log.Info("[VPN] peer face listening",
		"peer_port", p.opts.PeerPort,
		"tcp", tcpLn.Addr().String(),
		"udp", udpLn.Addr().String())

	p.wg.Add(2)
	go func() {
		defer p.wg.Done()
		if err := socks.ServeBorrowed(countingListener{tcpLn}); err != nil {
			log.Error("[VPN] peer face tcp serve", "err", err)
		}
	}()
	go func() {
		defer p.wg.Done()
		if err := p.relay.Serve(udpLn); err != nil {
			log.Error("[VPN] peer face udp serve", "err", err)
		}
	}()

	return nil
}

// Stop 关闭对端面：先关监听器，再收 UDP 在飞流，最后关 tailcat Server。
// 顺序反了会让在飞连接在隧道消失后才拆除；幂等，未 Start 时是空操作。
func (p *PeerFace) Stop() error {
	p.stopOnce.Do(func() {
		if p.tcpLn != nil {
			_ = p.tcpLn.Close()
		}
		if p.udpLn != nil {
			_ = p.udpLn.Close()
		}
		p.wg.Wait()

		if p.relay != nil {
			p.relay.Close()
		}
		if p.socks != nil {
			if err := p.socks.Close(); err != nil {
				p.stopErr = err
			}
		}
		if p.srv != nil {
			if err := p.srv.Close(); err != nil && p.stopErr == nil {
				p.stopErr = err
			}
			p.srv = nil
		}
	})
	return p.stopErr
}

// PublishAddr 把本节点的 tailcat 地址写到 path（见 PeerFacePath），并返回该地址。
// 写前重新自检完整格式；目录 0700、文件 0600——地址含 preshared key，等价于接入凭据。
func (p *PeerFace) PublishAddr(path string) (string, error) {
	addr := p.TailcatAddr()
	if err := AssertFullAddr(addr); err != nil {
		return "", fmt.Errorf("vpn: refusing to publish an unusable address: %w", err)
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return "", fmt.Errorf("vpn: create state dir %s: %w", dir, err)
		}
	}
	content := []byte(addr + "\n")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, content, 0o600); err != nil {
		return "", fmt.Errorf("vpn: write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("vpn: rename %s: %w", tmp, err)
	}
	return addr, nil
}

// LoopbackDialContext 是对端面唯一的拨号器：只接受**字面** loopback 目标。
// 这是整个 VPN 的安全边界：不做名字解析，域名（含 "localhost"）与其他目标一律拒绝，
// 因此不依赖 DNS 是否可信，也不可能成为内网跳板。
func LoopbackDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("vpn: peer face rejected target %q: %w", addr, err)
	}
	ip, err := loopbackIP(host)
	if err != nil {
		return nil, err
	}
	portNum, err := parsePort(port)
	if err != nil {
		return nil, fmt.Errorf("vpn: peer face rejected target %q: %w", addr, err)
	}
	// 用解析后的字面地址拨号：字符串里不可能再出现需要解析的名字。
	return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort(ip.String(), strconv.Itoa(portNum)))
}

// countingListener 在监听器层统计对端面接受的 TCP 流。
// 只在 Accept 成功后计数：Socks5Server 没有接受回调，而失败的 Accept 不算一条流。
type countingListener struct{ net.Listener }

func (l countingListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err == nil {
		stats.RecordVPNPeerFaceStream()
	}
	return conn, err
}
