package nextproxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/protocol"
	"github.com/nange/easyss/v3/util/bytespool"
	"github.com/xjasonlyu/tun2socks/v2/transport/socks5"
)

// next proxy 的 SOCKS5 UDP 转发（RFC 1928 §7 的 UDP ASSOCIATE）。x/net/proxy 的 SOCKS5
// 拨号器只实现 CONNECT，因此协议层交给 tun2socks 的库。
const (
	// udpBufSize 与 server/handler 的 UDP 会话共用 protocol.MaxUDPDataSize，两个方向的边界
	// 因此一致：会话收得下的数据报，这里也必须封得出来。
	udpBufSize = protocol.MaxUDPDataSize

	// maxUDPDatagram 是载荷上限加最坏情况的头（RSV/FRAG + ATYP + IPv6 地址 + 端口），
	// 正好等于数据报链路的池档位（16KB）。
	maxUDPDatagram = udpBufSize + 3 + 1 + net.IPv6len + 2
)

// 关联请求的 DST 填 0.0.0.0:0：我们只用一条未绑定的 socket 发送，通告 "unspecified" 是
// RFC 1928 允许且最不依赖客户端网络位置的形式。
func (np *NextProxy) dialUDPAssociate(ctx context.Context, dst string) (net.Conn, error) {
	if !np.enableUDP {
		return nil, errors.New("udp forwarding is not enabled for the next proxy")
	}
	if np.url == nil {
		return nil, errors.New("next proxy url is not configured")
	}

	// 先编码并校验目标：Write 是逐数据报的热路径，编码只能做一次。
	target, err := encodeDatagramTarget(dst)
	if err != nil {
		return nil, err
	}

	control, deadline, err := np.dialProxyTCP(ctx)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (net.Conn, error) {
		control.Close() //nolint:errcheck
		return nil, err
	}
	// 凭据只在有值时传入：库据此通告单个认证方法（有凭据即用户名/密码，否则无需认证）。
	var user *socks5.User
	if u, p, ok := np.credentials(); ok {
		user = &socks5.User{Username: u, Password: p}
	}
	bindAddr, err := socks5.ClientHandshake(control, socks5.ParseAddrString("0.0.0.0:0"), socks5.CmdUDPAssociate, user)
	if err != nil {
		return fail(fmt.Errorf("udp associate: %w", err))
	}
	relayAddr, err := resolveRelayAddr(bindAddr, control.RemoteAddr())
	if err != nil {
		return fail(err)
	}

	relay, err := net.DialUDP(udpNetworkFor(relayAddr.IP), localAddrFor(control, relayAddr.IP), relayAddr)
	if err != nil {
		return fail(fmt.Errorf("dial the udp relay %s: %w", relayAddr, err))
	}

	c := &udpAssociateConn{control: control, relay: relay, dst: target, closed: make(chan struct{})}

	if !deadline.IsZero() {
		// 拨号截止时间的剩余额度不该泄漏到数据面：长会话的静默期可以远超拨号超时。
		if err := control.SetDeadline(time.Time{}); err != nil {
			relay.Close() //nolint:errcheck
			return fail(err)
		}
	}

	// 控制连接是关联的存活信号（RFC 1928：控制连接终止即关联终止）。
	go c.monitorControl()
	return c, nil
}

// 补上库缺失的长度校验：socks5.ParseAddrString 对域名只写 uint8(len(domain)) 而不做范围
// 检查，256 字节的名字会写成长度 0x00 并仍跟着完整名字。
func encodeDatagramTarget(dst string) (socks5.Addr, error) {
	addr := socks5.ParseAddrString(dst)
	if addr == nil {
		return nil, fmt.Errorf("malformed datagram target %q", dst)
	}
	if len(addr) > socks5.MaxAddrLen {
		return nil, fmt.Errorf("datagram target %q is too long for socks5 (%d > %d bytes)",
			dst, len(addr), socks5.MaxAddrLen)
	}
	return addr, nil
}

// 解析应答里的 BND.ADDR:BND.PORT。上游应答通配地址（0.0.0.0:port）表示"就在你连我的这个
// 地址上监听"，必须换成控制连接的对端地址；应答域名时库的 UDPAddr() 返回 nil，要自己解析。
func resolveRelayAddr(bindAddr socks5.Addr, controlRemote net.Addr) (*net.UDPAddr, error) {
	if !bindAddr.Valid() {
		return nil, fmt.Errorf("invalid udp relay address in the associate reply: %#v", []byte(bindAddr))
	}
	if bindAddr[0] == socks5.AtypDomainName {
		// 解析成字面 IP，数据面不必每条数据报都解析一次。
		host, port, err := splitSocksAddr(bindAddr)
		if err != nil {
			return nil, err
		}
		resolved, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, strconv.Itoa(port)))
		if err != nil {
			return nil, fmt.Errorf("resolve the udp relay %s: %w", host, err)
		}
		return resolved, nil
	}

	relay := bindAddr.UDPAddr()
	if relay == nil {
		return nil, fmt.Errorf("invalid udp relay address in the associate reply: %#v", []byte(bindAddr))
	}
	if !relay.IP.IsUnspecified() {
		return relay, nil
	}

	host, _, err := net.SplitHostPort(controlRemote.String())
	if err != nil {
		return nil, fmt.Errorf("resolve the udp relay from %s: %w", controlRemote, err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		resolved, resolveErr := net.ResolveUDPAddr("udp", net.JoinHostPort(host, strconv.Itoa(relay.Port)))
		if resolveErr != nil {
			return nil, fmt.Errorf("resolve the upstream proxy address %s: %w", host, resolveErr)
		}
		ip = resolved.IP
	}
	return &net.UDPAddr{IP: ip, Port: relay.Port}, nil
}

func splitSocksAddr(addr socks5.Addr) (string, int, error) {
	if len(addr) < 1+1+2 {
		return "", 0, fmt.Errorf("short socks5 address: %d bytes", len(addr))
	}
	length := int(addr[1])
	if len(addr) < 1+1+length+2 {
		return "", 0, fmt.Errorf("short socks5 address: claims %d name bytes", length)
	}
	port := int(addr[len(addr)-2])<<8 | int(addr[len(addr)-1])
	return string(addr[2 : 2+length]), port, nil
}

// 把本地地址钉在控制连接所用的接口地址上，上游才可能接受这些数据报。与中继地址同族时才
// 可用，否则返回 nil 让内核按路由表选择。
func localAddrFor(control net.Conn, relayIP net.IP) *net.UDPAddr {
	host, _, err := net.SplitHostPort(control.LocalAddr().String())
	if err != nil {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil || udpAddrFamily(ip) != udpAddrFamily(relayIP) {
		return nil
	}
	return &net.UDPAddr{IP: ip}
}

func udpAddrFamily(ip net.IP) int {
	if ip.To4() != nil {
		return 4
	}
	if ip.To16() != nil {
		return 6
	}
	return 0
}

// 让中继地址的族决定本地 socket 的族，双栈主机上的系统默认值可能与中继地址不符。
func udpNetworkFor(ip net.IP) string {
	if udpAddrFamily(ip) == 6 {
		return "udp6"
	}
	return "udp4"
}

// DNS 应答可能来自与查询目标不同的 IP，而 net.Conn 契约不带来源地址，因此写按固定的 dst
// 封帧发给中继地址，读只剥封装。
type udpAssociateConn struct {
	control net.Conn
	relay   *net.UDPConn
	// dst 是本会话经上游转发的目标地址，已编码为 SOCKS5 地址。
	dst socks5.Addr

	closeOnce sync.Once
	// closed 让 monitorControl 区分"上游撤销了关联"与"我们自己收尾"，只有前者值得告警。
	closed chan struct{}
	// writeMu 串行化发送：udpHandler 只在主 goroutine 里写，但 net.Conn 契约不承诺这点。
	writeMu sync.Mutex
	// readMu 串行化"收包 → 解封装 → 拷贝"这一整次 Read，保证每条关联至多一块缓冲在飞。
	readMu sync.Mutex
}

// 上游关闭控制连接时立即关闭中继 socket，让阻塞中的 Read 返回而不是僵死到会话空闲超时。必须在这里
// 留日志：server/handler 的 targetReadError 把 net.ErrClosed 归一成 io.EOF，两者在那边无法区分。
func (c *udpAssociateConn) monitorControl() {
	buf := make([]byte, 1)
	for {
		if _, err := c.control.Read(buf); err != nil {
			if !c.isClosed() {
				log.Warn("[NEXTPROXY] udp association closed by the upstream proxy, tearing down the datagram side",
					"proxy", c.control.RemoteAddr(), "relay", c.relay.RemoteAddr(), "err", err)
			}
			c.Close() //nolint:errcheck
			return
		}
		// 关联建立后上游不应再发送任何字节，收到就丢弃，保持读取以便继续感知关闭。
	}
}

// isClosed 未初始化 closed 时按"未关闭"处理。
func (c *udpAssociateConn) isClosed() bool {
	if c.closed == nil {
		return false
	}
	select {
	case <-c.closed:
		return true
	default:
		return false
	}
}

// 逐次借还接收缓冲，常驻会让空闲关联各钉住一整档。必须用 bytespool.Get(maxUDPDatagram) 而非
// make/append，否则 MustPut 会因 cap 不是 2 的幂 panic；归还时传完整切片，不能传 append 出来的拷贝。
func (c *udpAssociateConn) Read(b []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	buf := bytespool.Get(maxUDPDatagram)
	defer bytespool.MustPut(buf)

	for {
		n, _, err := c.relay.ReadFromUDP(buf)
		if err != nil {
			if protocol.IsUDPMessageTooLong(err) {
				log.Warn("[NEXTPROXY] dropping oversized udp datagram", "err", err)
				continue
			}
			return 0, err
		}
		// 读满档位既可能是合法上限也可能被内核截断，二者无法区分，而转发截断的载荷比丢弃更糟。
		if n == len(buf) {
			log.Warn("[NEXTPROXY] dropping truncated udp datagram", "n", n,
				"limit", udpBufSize)
			continue
		}
		_, payload, err := socks5.DecodeUDPPacket(buf[:n])
		if err != nil {
			// 坏数据报整条丢弃（RFC 1928 允许），不能返回 0,nil：上层会把 0 字节读取
			// 当成合法空数据报转发给客户端应用。
			continue
		}
		// 档位之下的整包仍可能解析出超过预算的载荷，超过就丢弃，避免记录缓冲跨出 16KB 档位。
		if len(payload) > udpBufSize {
			log.Warn("[NEXTPROXY] dropping oversized udp datagram",
				"payload", len(payload), "limit", udpBufSize)
			continue
		}
		// payload 别名 buf，但它返回前就被拷进调用方的 b，buf 可以立即归还。
		return copy(b, payload), nil
	}
}

func (c *udpAssociateConn) Write(b []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	packet, err := socks5.EncodeUDPPacket(c.dst, b)
	if err != nil {
		return 0, err
	}
	if _, err := c.relay.Write(packet); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *udpAssociateConn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		// closed 可能为 nil（测试直接构造零值），关闭 nil 通道会 panic。
		if c.closed != nil {
			close(c.closed)
		}
		err = c.relay.Close()
		if cerr := c.control.Close(); err == nil {
			err = cerr
		}
	})
	return err
}

func (c *udpAssociateConn) LocalAddr() net.Addr  { return c.relay.LocalAddr() }
func (c *udpAssociateConn) RemoteAddr() net.Addr { return c.relay.RemoteAddr() }

func (c *udpAssociateConn) SetDeadline(t time.Time) error {
	if err := c.relay.SetReadDeadline(t); err != nil {
		return err
	}
	return c.relay.SetWriteDeadline(t)
}

func (c *udpAssociateConn) SetReadDeadline(t time.Time) error {
	return c.relay.SetReadDeadline(t)
}

func (c *udpAssociateConn) SetWriteDeadline(t time.Time) error {
	return c.relay.SetWriteDeadline(t)
}
