package vpnnode

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/things-go/go-socks5/statute"

	sharedconfig "github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/stats"
)

// innerTargetHost 是访问侧写进隧道内 CONNECT 的目标主机，恒为字面 127.0.0.1。
//
// 隧道里的"目标"表达的是**对端的哪个服务端口**，而不是对端的网络位置——位置由
// tailcat 地址本身决定。用 127.0.0.1 而不是对端的 host_name 或 overlay IP 有两条
// 好处：对端面的拨号器只接受字面 loopback（安全边界因此可证，见
// LoopbackDialContext），且隧道里不会出现任何只在访问侧才有意义的名字。
// 这是两端唯一的跨节点协议契约（见 docs/vpn-design.md 5.1）。
const innerTargetHost = "127.0.0.1"

// RouteOptions 是构造访问侧所需的输入。
type RouteOptions struct {
	// Overlay 提供「host_name / overlay 字面 IP → 对端」的映射。
	Overlay *Overlay
	// Clients 提供经隧道的拨号能力。
	Clients *ClientSet
	// Timeouts 提供拨号与内层握手超时（复用客户端既有的一套派生值）。
	Timeouts sharedconfig.Timeouts
}

// Route 是访问侧：把"对端 + 对端端口"变成一条可用的连接。
//
// 它实现 client/proxy 的 VPNRoute 接口（接口定义在消费方，因为 vpn/node 已经
// 依赖 client/proxy——对端面复用的正是那个 Socks5Server）。因此代理层只需要知道
// "是不是对端"与"给我一条连接"，隧道、内层握手与目标归一化全部留在这里。
type Route struct {
	overlay     *Overlay
	clients     *ClientSet
	dialTimeout time.Duration
}

// NewRoute 构造访问侧。
func NewRoute(opts RouteOptions) (*Route, error) {
	if opts.Overlay == nil {
		return nil, errors.New("vpn: route requires an overlay")
	}
	if opts.Clients == nil {
		return nil, errors.New("vpn: route requires a client set")
	}
	dialTimeout := opts.Timeouts.Dial
	if dialTimeout <= 0 {
		dialTimeout = sharedconfig.DefaultDialTimeout
	}
	return &Route{overlay: opts.Overlay, clients: opts.Clients, dialTimeout: dialTimeout}, nil
}

// Lookup 实现 proxy.VPNRoute：host 可以是 host_name（不区分大小写）或 overlay
// 字面 IP，返回值是对端的规范名（host_name 的书写形式）。
func (r *Route) Lookup(host string) (string, bool) {
	ref, ok := r.overlay.Lookup(host)
	if !ok {
		return "", false
	}
	return ref.HostName, true
}

// DialTCP 打开一条经隧道到对端服务端口的 TCP 连接：先建立（或复用）到对端的
// tailcat 隧道，再在隧道内对它自己的对端面做一次 SOCKS5 CONNECT，目标固定为
// <innerTargetHost>:port。
func (r *Route) DialTCP(ctx context.Context, target string) (net.Conn, error) {
	ref, port, err := r.peerFor(target)
	if err != nil {
		return nil, err
	}
	client, err := r.clients.clientFor(ref.Address)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(ctx, r.dialTimeout)
	defer cancel()
	// 只拨对端在隧道内的对端面端口：对端的其他服务端口由对端面代为拨号，因此
	// 访问侧不需要（也无法）知道它们。地址不写进错误信息——它内嵌 preshared
	// key，等价于对端面的接入凭据（见 docs/vpn-design.md 第 7 节）。
	conn, err := client.DialTCPPort(ctx, uint16(ref.Port))
	if err != nil {
		stats.RecordVPNDialError()
		return nil, fmt.Errorf("vpn: dial peer %q through the tunnel: %w", ref.HostName, err)
	}

	// 内层握手要有自己的截止时间，但**必须在握手之后清掉**：否则这条连接会带着
	// 一个固定的绝对截止时间进入中继阶段，一条空闲的 SSH 会话会在那一刻被无声
	// 切断。不支持 deadline 的实现不影响功能，只意味着内层握手可能挂住。
	if derr := conn.SetDeadline(time.Now().Add(r.dialTimeout)); derr != nil {
		log.Debug("[VPN] set inner handshake deadline", "target", target, "err", derr)
	}
	if err := socks5Connect(conn, port); err != nil {
		stats.RecordVPNDialError()
		_ = conn.SetDeadline(time.Time{})
		_ = conn.Close()
		return nil, fmt.Errorf("vpn: peer %q rejected %s: %w", ref.HostName, target, err)
	}
	_ = conn.SetDeadline(time.Time{})

	stats.RecordVPNTCPStream()
	return conn, nil
}

// DialUDP 打开一条经隧道到对端服务端口的 UDP 流。返回的连接在首次写入时自动补上
// 一次性目标头（同样是 <innerTargetHost>:port），因此调用方按普通 net.Conn 收发
// 数据报即可。
func (r *Route) DialUDP(ctx context.Context, target string) (net.Conn, error) {
	ref, port, err := r.peerFor(target)
	if err != nil {
		return nil, err
	}
	client, err := r.clients.clientFor(ref.Address)
	if err != nil {
		return nil, err
	}
	header, err := EncodeUDPTarget(net.JoinHostPort(innerTargetHost, strconv.Itoa(port)))
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(ctx, r.dialTimeout)
	defer cancel()
	conn, err := client.DialUDPPort(ctx, uint16(ref.Port))
	if err != nil {
		stats.RecordVPNDialError()
		return nil, fmt.Errorf("vpn: dial peer %q udp through the tunnel: %w", ref.HostName, err)
	}
	stats.RecordVPNUDPFlow()
	return &targetHeaderConn{Conn: conn, header: header}, nil
}

// peerFor 把访问侧看到的目标（host:port）解析成对端与对端上的端口。
//
// host 必须是已配置的对端名或它的 overlay IP；port 是对端本机的服务端口。这两者
// 都不进隧道——隧道里只有 innerTargetHost 与 port。
func (r *Route) peerFor(target string) (PeerRef, int, error) {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return PeerRef{}, 0, fmt.Errorf("vpn: invalid target %q: %w", target, err)
	}
	ref, ok := r.overlay.Lookup(host)
	if !ok {
		return PeerRef{}, 0, fmt.Errorf("vpn: %q is not a configured peer", host)
	}
	// PeerRef.Port 已经由 NewConfig 归一化过；这里再拦一次是因为通往 tailcat 的
	// uint16 转换是静默截断的，一个越界值会变成另一个端口。
	if ref.Port < 1 || ref.Port > 65535 {
		return PeerRef{}, 0, fmt.Errorf("vpn: peer %q has an invalid peer port %d", ref.HostName, ref.Port)
	}
	port, err := parsePort(portStr)
	if err != nil {
		return PeerRef{}, 0, fmt.Errorf("vpn: invalid target %q: %w", target, err)
	}
	return ref, port, nil
}

// socks5Connect 在一条隧道内的连接上完成 SOCKS5 握手与 CONNECT，目标为
// <innerTargetHost>:port。它就是"访问侧是客户端、对端面是服务端"的那一半契约。
//
// 只用无认证方式：对端面是本进程按固定参数构造的（见 PeerFace.Start 不设置
// Username/Password），因此一个要求认证的应答意味着对端不是我们的对端面，报错
// 比假装成功更有用。
func socks5Connect(conn net.Conn, port int) error {
	greeting := statute.NewMethodRequest(statute.VersionSocks5, []byte{statute.MethodNoAuth})
	if _, err := conn.Write(greeting.Bytes()); err != nil {
		return fmt.Errorf("write the socks5 greeting: %w", err)
	}
	var reply [2]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil {
		return fmt.Errorf("read the socks5 greeting reply: %w", err)
	}
	if reply[0] != statute.VersionSocks5 || reply[1] != statute.MethodNoAuth {
		return fmt.Errorf("the peer face does not accept unauthenticated socks5 (method reply %#x %#x)", reply[0], reply[1])
	}

	dst, err := statute.ParseAddrSpec(net.JoinHostPort(innerTargetHost, strconv.Itoa(port)))
	if err != nil {
		return fmt.Errorf("build the socks5 target: %w", err)
	}
	req := statute.Request{
		Version:  statute.VersionSocks5,
		Command:  statute.CommandConnect,
		Reserved: 0,
		DstAddr:  dst,
	}
	if _, err := conn.Write(req.Bytes()); err != nil {
		return fmt.Errorf("write the socks5 connect request: %w", err)
	}
	rep, err := statute.ParseReply(conn)
	if err != nil {
		return fmt.Errorf("read the socks5 connect reply: %w", err)
	}
	if rep.Response != statute.RepSuccess {
		return fmt.Errorf("the peer face refused the connection (socks5 reply %d)", rep.Response)
	}
	return nil
}

// targetHeaderConn 在首次写入前把一次性目标头插进**同一条数据报**。
//
// 头必须与首个载荷合在一起：对端面按"每条隧道 UDP 流一个目标"处理，目标由流的
// 第一个数据报解出（见 DecodeUDPTarget）。分开写会让目标确定与首个载荷各占一条
// 数据报，多条一次无谓的往返，且一旦那条只有头的数据报丢失，该流就永远停在
// "没有目标"的状态。
type targetHeaderConn struct {
	net.Conn

	header []byte

	// mu 使"只插一次"在并发写入下也成立。SOCKS5 UDP 中继目前是单 goroutine 调用
	// Write，但这条连接的写入方不受本类型控制，一次重复插入就会把目标头当载荷
	// 发给对端。
	mu   sync.Mutex
	sent bool
}

func (c *targetHeaderConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.sent {
		return c.Conn.Write(p)
	}
	c.sent = true

	buf := make([]byte, 0, len(c.header)+len(p))
	buf = append(buf, c.header...)
	buf = append(buf, p...)
	if _, err := c.Conn.Write(buf); err != nil {
		return 0, err
	}
	return len(p), nil
}
