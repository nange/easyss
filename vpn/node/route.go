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

	tailcat "github.com/tailscale/tailcat"
	"github.com/things-go/go-socks5/statute"

	"github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/stats"
)

// innerTargetHost 是访问侧写进隧道内 CONNECT 的目标主机，恒为字面 127.0.0.1。
// 目标表达的是"对端的哪个服务端口"而不是位置；对端面只接受字面 loopback，因此这是
// 两端唯一的跨节点协议契约。
const innerTargetHost = "127.0.0.1"

type RouteOptions struct {
	// Overlay 提供「host_name / overlay 字面 IP → 对端」的映射。
	Overlay *Overlay
	Clients *ClientSet
	// Timeouts 提供拨号与内层握手超时；Dial 零值由 Timeouts.Normalize 补齐。
	Timeouts config.Timeouts
}

// Route 是访问侧：把"对端 + 对端端口"变成一条可用的连接。
// 实现 client/proxy 的 VPNRoute（接口定义在消费方，否则与 vpn/node 形成导入环）。
type Route struct {
	overlay     *Overlay
	clients     *ClientSet
	dialTimeout time.Duration
}

func NewRoute(opts RouteOptions) (*Route, error) {
	if opts.Overlay == nil {
		return nil, errors.New("vpn: route requires an overlay")
	}
	if opts.Clients == nil {
		return nil, errors.New("vpn: route requires a client set")
	}
	// 零值由 Timeouts.Normalize 补齐，与其它公开构造器走同一个入口。
	dialTimeout := opts.Timeouts.Normalize().Dial
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
	// key，等价于对端面的接入凭据。
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
// host 必须是已配置的对端名或 overlay IP，port 是对端本机的服务端口；两者都不进隧道。
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

// socks5Connect 在隧道内连接上完成 SOCKS5 握手与 CONNECT，目标为 <innerTargetHost>:port。
// 只用无认证方式：对端面固定不设 Username/Password，要求认证的应答说明对端不是我们的对端面。
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
// 对端面按"每条隧道 UDP 流一个目标"处理，目标只从第一个数据报解出（见 DecodeUDPTarget）；
// 头单独发一条数据报会让该流在该包丢失后永远没有目标。
type targetHeaderConn struct {
	net.Conn

	header []byte

	// mu 使"只插一次"在并发写入下也成立。SOCKS5 UDP 中继是单 goroutine 调用
	// Write，但这条连接的写入方不受本类型控制，一次重复插入就会把目标头当载荷
	// 发给对端。
	mu   sync.Mutex
	sent bool
}

func (c *targetHeaderConn) Write(p []byte) (int, error) {
	// 载荷超过隧道的单包上限时对端收不到完整数据报（见 tailcat.MaxUDPPayload）；在这里
	// 明确拒绝并记一条日志（调用方对写入错误只记 Debug，这条需要可行动），而不是交给
	// 隧道截断或分片后由对端悄悄丢弃。
	if len(p) > tailcat.MaxUDPPayload {
		log.Warn("[VPN] dropping an oversized UDP datagram", "payload", len(p), "limit", tailcat.MaxUDPPayload)
		return 0, fmt.Errorf("vpn: UDP payload of %d bytes exceeds the tunnel limit of %d", len(p), tailcat.MaxUDPPayload)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.sent {
		return c.Conn.Write(p)
	}

	buf := make([]byte, 0, len(c.header)+len(p))
	buf = append(buf, c.header...)
	buf = append(buf, p...)
	if _, err := c.Conn.Write(buf); err != nil {
		// 首包失败时不能标记已发：否则这条流之后的每个数据报都不带目标头，对端会一直
		// 拒绝，直到会话池按空闲把它回收。
		return 0, err
	}
	c.sent = true
	return len(p), nil
}
