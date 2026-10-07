package nextproxy

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

// 本文件实现 next proxy 的 SOCKS5 UDP 转发（RFC 1928 §7 的 UDP ASSOCIATE）。
//
// 它由两部分组成，缺一不可：
//
//   - 一次关联：到上游代理的 TCP 控制连接 + 一条 UDP ASSOCIATE 命令，上游在
//     应答（BND.ADDR:BND.PORT）里给出中继地址。关联的生命周期等同于这条 TCP
//     连接的生命周期——所以控制连接必须一直开着，并由本连接的 Close 收尾。
//   - 逐数据报封帧：RSV(2)/FRAG(1)/ATYP/DST.ADDR/DST.PORT/DATA，经中继地址
//     发给上游。FRAG 恒为 0（本实现不支持分片，RFC 1928 允许整条丢弃）。
//
// 这正是 x/net/proxy 的 SOCKS5 拨号器不提供的能力：它只实现 CONNECT，把
// network="udp" 交给它只会得到一次注定失败的 TCP 拨号。
const (
	socksVersion5 = 0x05

	socksCmdUDPAssociate = 0x03

	socksReplySucceeded = 0x00

	socksAuthVersion      = 0x01
	socksAuthStatusOK     = 0x00
	socksAuthNoneRequired = 0x00
	socksAuthUserPass     = 0x02
	socksAuthNoAcceptable = 0xff

	socksATYPIPv4 = 0x01
	socksATYPFQDN = 0x03
	socksATYPIPv6 = 0x04

	socksPortLen = 2

	// udpAssociateReadBuffer 是读取上游 SOCKS5 中继数据报的缓冲区大小。
	// UDP 数据报不可能超过 64KB，一次分配即可覆盖任何合法数据报。
	udpAssociateReadBuffer = 64 * 1024
)

// dialUDPAssociate 与上游 SOCKS5 代理建立一次 UDP 关联，并返回一个 net.Conn：
// 每次 Write 把载荷作为一个数据报经上游转发，每次 Read 返回中继回来的载荷。
//
// 关联请求里的 DST.ADDR/DST.PORT 填 0.0.0.0:0：那是"客户端将用来发送数据报的
// 地址"；我们只用一条未绑定的 socket 发送，明确通告 "unspecified" 是 RFC 1928
// 允许且最不依赖客户端网络位置的形式。
func (np *NextProxy) dialUDPAssociate(ctx context.Context, dst string) (net.Conn, error) {
	if !np.enableUDP {
		// 调用方（udpHandler 的 shouldProxy）已经用 EnableUDP() 门控过一次，
		// 这里是纵深防御：配置关闭时绝不悄悄建立关联。
		return nil, errors.New("udp forwarding is not enabled for the next proxy")
	}
	if np.url == nil {
		return nil, errors.New("next proxy url is not configured")
	}

	control, deadline, err := np.dialProxyTCP(ctx)
	if err != nil {
		return nil, err
	}
	// 后续每个失败分支都要关掉控制连接（关联本身也由它承载）。
	fail := func(err error) (net.Conn, error) {
		control.Close() //nolint:errcheck
		return nil, err
	}

	if err := np.negotiate(control); err != nil {
		return fail(err)
	}

	// UDP ASSOCIATE 请求：VER CMD RSV ATYP(IPv4) 0.0.0.0 0
	req := []byte{socksVersion5, socksCmdUDPAssociate, 0x00, socksATYPIPv4, 0, 0, 0, 0, 0, 0}
	if _, err := control.Write(req); err != nil {
		return fail(fmt.Errorf("send udp associate: %w", err))
	}
	relayHost, relayPort, err := readSocks5Reply(control)
	if err != nil {
		return fail(fmt.Errorf("udp associate reply: %w", err))
	}

	// 上游可能应答一个通配地址（0.0.0.0:port），表示"就在你连我的这个地址上
	// 监听"。0.0.0.0 无法作为发送目标，必须替换成控制连接的对端地址。
	relayIP := net.ParseIP(relayHost)
	if relayIP == nil {
		// 应答里是域名：解析成字面 IP，避免每条数据报都依赖一次解析。
		resolved, resolveErr := net.ResolveUDPAddr(udpNetworkFor(net.IPv4zero), net.JoinHostPort(relayHost, strconv.Itoa(relayPort)))
		if resolveErr != nil {
			return fail(fmt.Errorf("resolve the udp relay %s: %w", relayHost, resolveErr))
		}
		relayIP = resolved.IP
	}
	if relayIP.IsUnspecified() {
		proxyHost, _, splitErr := net.SplitHostPort(control.RemoteAddr().String())
		if splitErr != nil {
			return fail(fmt.Errorf("resolve the udp relay from %s: %w", control.RemoteAddr(), splitErr))
		}
		if ip := net.ParseIP(proxyHost); ip != nil {
			relayIP = ip
		} else {
			resolved, resolveErr := net.ResolveUDPAddr("udp", net.JoinHostPort(proxyHost, strconv.Itoa(relayPort)))
			if resolveErr != nil {
				return fail(fmt.Errorf("resolve the upstream proxy address %s: %w", proxyHost, resolveErr))
			}
			relayIP = resolved.IP
		}
	}

	relayAddr := &net.UDPAddr{IP: relayIP, Port: relayPort}
	relay, err := net.DialUDP(udpNetworkFor(relayIP), localAddrFor(control, relayIP), relayAddr)
	if err != nil {
		return fail(fmt.Errorf("dial the udp relay %s: %w", relayAddr, err))
	}

	if !deadline.IsZero() {
		// 握手与关联都已完成，清除拨号截止时间：它的剩余额度不该泄漏到数据面
		// ——一次长会话里的静默期可以远超拨号超时。
		if err := control.SetDeadline(time.Time{}); err != nil {
			relay.Close() //nolint:errcheck
			return fail(err)
		}
	}

	c := &udpAssociateConn{control: control, relay: relay, dst: dst}
	// 控制连接是关联的存活信号：上游一旦关闭它，这个关联就不再有效，必须
	// 立即终止本地 socket，而不是让调用方一直阻塞在 Read 上。
	go c.monitorControl()
	return c, nil
}

// negotiate 协商认证方式：先通告支持的方法（无认证 + 用户名/密码），再按上游
// 的选择执行认证。它与 x/net/proxy 的 CONNECT 路径保持同一套语义，使同一条
// URL 上的 TCP 与 UDP 走完全一致的认证行为。
func (np *NextProxy) negotiate(conn net.Conn) error {
	user, password, hasAuth := np.credentials()
	methods := []byte{socksAuthNoneRequired}
	if hasAuth {
		methods = append(methods, socksAuthUserPass)
	}

	req := make([]byte, 0, 2+len(methods))
	req = append(req, socksVersion5, byte(len(methods)))
	req = append(req, methods...)
	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("send auth methods: %w", err)
	}

	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return fmt.Errorf("read auth method: %w", err)
	}
	if resp[0] != socksVersion5 {
		return fmt.Errorf("unexpected protocol version %d", resp[0])
	}
	switch resp[1] {
	case socksAuthNoneRequired:
		return nil
	case socksAuthUserPass:
		if !hasAuth {
			return errors.New("the upstream proxy requires username/password authentication")
		}
		return authenticateUserPass(conn, user, password)
	case socksAuthNoAcceptable:
		if hasAuth {
			return errors.New("no acceptable authentication methods")
		}
		return errors.New("the upstream proxy requires authentication but the next proxy url carries no credentials")
	default:
		return fmt.Errorf("unsupported authentication method %#x", resp[1])
	}
}

// authenticateUserPass 执行 RFC 1929 的用户名/密码认证。
func authenticateUserPass(conn net.Conn, user, password string) error {
	if len(user) == 0 || len(user) > 255 || len(password) > 255 {
		return errors.New("invalid username/password")
	}
	req := make([]byte, 0, 3+len(user)+len(password))
	req = append(req, socksAuthVersion, byte(len(user)))
	req = append(req, user...)
	req = append(req, byte(len(password)))
	req = append(req, password...)
	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("send credentials: %w", err)
	}

	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return fmt.Errorf("read auth status: %w", err)
	}
	if resp[0] != socksAuthVersion {
		return fmt.Errorf("invalid username/password version %d", resp[0])
	}
	if resp[1] != socksAuthStatusOK {
		return errors.New("username/password authentication failed")
	}
	return nil
}

// readSocks5Reply 读取并校验一条命令应答，返回其中的 BND.ADDR 与 BND.PORT。
// 应答里的地址可能是域名（上游只会在极少数部署里这么做），因此返回主机字符串
// 而不假定是 IP，由调用方决定是否解析。
func readSocks5Reply(conn net.Conn) (host string, port int, err error) {
	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		return "", 0, err
	}
	if head[0] != socksVersion5 {
		return "", 0, fmt.Errorf("unexpected protocol version %d", head[0])
	}
	if head[1] != socksReplySucceeded {
		return "", 0, fmt.Errorf("upstream proxy rejected the request: %s", socksReplyString(head[1]))
	}
	host, err = readSocks5Addr(conn, head[3])
	if err != nil {
		return "", 0, err
	}
	portBytes := make([]byte, socksPortLen)
	if _, err := io.ReadFull(conn, portBytes); err != nil {
		return "", 0, err
	}
	return host, int(binary.BigEndian.Uint16(portBytes)), nil
}

// readSocks5Addr 读取一个 SOCKS5 地址，返回其主机部分（域名或 IP 字面量）。
func readSocks5Addr(r io.Reader, atyp byte) (string, error) {
	switch atyp {
	case socksATYPIPv4:
		buf := make([]byte, net.IPv4len)
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", err
		}
		return net.IP(buf).String(), nil
	case socksATYPIPv6:
		buf := make([]byte, net.IPv6len)
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", err
		}
		return net.IP(buf).String(), nil
	case socksATYPFQDN:
		length := make([]byte, 1)
		if _, err := io.ReadFull(r, length); err != nil {
			return "", err
		}
		buf := make([]byte, int(length[0]))
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", err
		}
		return string(buf), nil
	default:
		return "", fmt.Errorf("unsupported address type %#x", atyp)
	}
}

// socksReplyString 把应答码翻译成 RFC 1928 里的名字，便于排障时直接读懂日志。
func socksReplyString(code byte) string {
	switch code {
	case socksReplySucceeded:
		return "succeeded"
	case 0x01:
		return "general SOCKS server failure"
	case 0x02:
		return "connection not allowed by ruleset"
	case 0x03:
		return "network unreachable"
	case 0x04:
		return "host unreachable"
	case 0x05:
		return "connection refused"
	case 0x06:
		return "TTL expired"
	case 0x07:
		return "command not supported"
	case 0x08:
		return "address type not supported"
	default:
		return "unknown reply code " + strconv.Itoa(int(code))
	}
}

// localAddrFor 选择发送数据报的本地地址。上游可能要求客户端从中继地址所在的
// 主机发送数据报，因此优先把本地地址钉在控制连接所用的接口地址上——它与中继
// 地址同族时才可用，否则把 v4 地址绑给 v6 socket（或反之）只会让拨号失败。
// 找不到同族地址时返回 nil，让内核按路由表选择。
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

// udpAddrFamily 返回地址的 IP 族（4 或 6），无法归入任何一族时返回 0。
func udpAddrFamily(ip net.IP) int {
	if ip.To4() != nil {
		return 4
	}
	if ip.To16() != nil {
		return 6
	}
	return 0
}

// udpNetworkFor 返回与给定 IP 族匹配的 UDP network，使中继地址的族决定本地
// socket 的族，而不是依赖系统默认（双栈主机上的默认值可能与中继地址不符）。
func udpNetworkFor(ip net.IP) string {
	if udpAddrFamily(ip) == 6 {
		return "udp6"
	}
	return "udp4"
}

// udpAssociateConn 把一个已建立的 SOCKS5 UDP 关联伪装成 net.Conn，使
// udpHandler 的中继循环不必知道 SOCKS5 数据报封装的存在：它只看到"读到一个
// 数据报 / 写入一个数据报"。
//
// Write 把载荷封成一条 SOCKS5 UDP 数据报后发给中继地址，目标地址恒为关联时
// 上层给定的那个（udpHandler 每条会话只关心一个目标）。读方向剥掉封装：DNS
// 应答可能来自与查询目标不同的 IP，而 net.Conn 契约不带来源地址，上层按会话
// 区分目标，因此来源在这里被丢弃、载荷照常返回。
type udpAssociateConn struct {
	control net.Conn
	relay   *net.UDPConn
	// dst 是本会话经上游转发的目标地址（udpHandler 的一条会话只关心一个目标），
	// 用于给每条上行数据报写 SOCKS5 头。数据报的发送目的地是中继地址，由
	// relay 这条已连接 socket 自身承载（见 relay.RemoteAddr）。
	dst string

	closeOnce sync.Once
	// writeMu 串行化发送并保护 frameBuf：udpHandler 只在主 goroutine 里写，
	// 但 net.Conn 的契约不承诺这一点，而让并发的半截数据报交错会静默损坏流。
	writeMu  sync.Mutex
	frameBuf []byte
	// readMu 只保护 scratch：单次 Read 内完成"读取 → 解析 → 拷贝到调用方
	// 缓冲区"，因此不需要把整个读取过程串行化。
	readMu  sync.Mutex
	scratch []byte
}

// monitorControl 阻塞在控制连接上：上游关闭它（关联失效）或控制连接出错时，
// 立即关闭中继 socket，让阻塞中的 Read 返回，而不是僵死到会话空闲超时。
func (c *udpAssociateConn) monitorControl() {
	buf := make([]byte, 1)
	for {
		if _, err := c.control.Read(buf); err != nil {
			c.Close() //nolint:errcheck
			return
		}
		// 关联建立后上游不应再发送任何字节（数据面走 UDP 中继）。收到就丢弃，
		// 保持读取以便继续感知控制连接的关闭。
	}
}

func (c *udpAssociateConn) Read(b []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	if c.scratch == nil {
		c.scratch = make([]byte, udpAssociateReadBuffer)
	}
	n, _, err := c.relay.ReadFromUDP(c.scratch)
	if err != nil {
		return 0, err
	}
	_, payload, err := parseSocks5UDPDatagram(c.scratch[:n])
	if err != nil {
		// 畸形/无法解析的数据报：按 0 字节读取丢弃，让中继循环继续读下一条，
		// 而不是把一条坏数据报当成会话故障。
		return 0, nil
	}
	return copy(b, payload), nil
}

func (c *udpAssociateConn) Write(b []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	framed, err := frameSocks5UDPDatagram(c.dst, c.frameBuf[:0], b)
	if err != nil {
		return 0, err
	}
	c.frameBuf = framed
	if _, err := c.relay.Write(framed); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *udpAssociateConn) Close() error {
	var err error
	c.closeOnce.Do(func() {
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

// frameSocks5UDPDatagram 把一条载荷封成 SOCKS5 UDP 数据报：先按 dst（"host:port"，
// host 可以是 IP 字面量或域名——上游代理解析域名正是链式代理的用途之一）写出
// RSV/FRAG/ATYP/DST.ADDR/DST.PORT 头（追加到 buf 上，供调用方复用），再追加载荷。
func frameSocks5UDPDatagram(dst string, buf, payload []byte) ([]byte, error) {
	host, portStr, err := net.SplitHostPort(dst)
	if err != nil {
		return nil, fmt.Errorf("malformed datagram target %q: %w", dst, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 0 || port > 65535 {
		return nil, fmt.Errorf("malformed datagram target port %q", portStr)
	}

	// RSV(2) + FRAG(1)：本实现不支持分片，FRAG 恒为 0。
	buf = append(buf, 0, 0, 0)
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			buf = append(buf, socksATYPIPv4)
			buf = append(buf, ip4...)
		} else {
			// ParseIP 已保证 v4/v6 二选一，这里的 else 必然是 v6。
			buf = append(buf, socksATYPIPv6)
			buf = append(buf, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return nil, fmt.Errorf("datagram target name too long: %q", host)
		}
		buf = append(buf, socksATYPFQDN, byte(len(host)))
		buf = append(buf, host...)
	}
	buf = binary.BigEndian.AppendUint16(buf, uint16(port))
	return append(buf, payload...), nil
}

// parseSocks5UDPDatagram 剥掉一条 SOCKS5 UDP 数据报的封装，返回其来源地址与
// 载荷。它与 frameSocks5UDPDatagram 互为逆操作，也是它唯一的对端实现——两者的
// 边界判定（ATYP、长度、FRAG）因此在测试里逐条对齐。
func parseSocks5UDPDatagram(datagram []byte) (src string, payload []byte, err error) {
	// RSV(2) + FRAG(1) + ATYP(1)
	if len(datagram) < 4 {
		return "", nil, fmt.Errorf("short udp datagram: %d bytes", len(datagram))
	}
	if datagram[2] != 0 {
		return "", nil, errors.New("fragmented udp datagrams are not supported")
	}

	var host string
	offset := 4
	switch datagram[3] {
	case socksATYPIPv4:
		if len(datagram) < offset+net.IPv4len+socksPortLen {
			return "", nil, errors.New("short udp datagram: ipv4 header")
		}
		host = net.IP(datagram[offset : offset+net.IPv4len]).String()
		offset += net.IPv4len
	case socksATYPIPv6:
		if len(datagram) < offset+net.IPv6len+socksPortLen {
			return "", nil, errors.New("short udp datagram: ipv6 header")
		}
		host = net.IP(datagram[offset : offset+net.IPv6len]).String()
		offset += net.IPv6len
	case socksATYPFQDN:
		if len(datagram) < offset+1 {
			return "", nil, errors.New("short udp datagram: missing domain length")
		}
		length := int(datagram[offset])
		offset++
		if len(datagram) < offset+length+socksPortLen {
			return "", nil, errors.New("short udp datagram: fqdn header")
		}
		host = string(datagram[offset : offset+length])
		offset += length
	default:
		return "", nil, fmt.Errorf("unsupported address type %#x", datagram[3])
	}

	port := binary.BigEndian.Uint16(datagram[offset : offset+socksPortLen])
	offset += socksPortLen
	return net.JoinHostPort(host, strconv.Itoa(int(port))), datagram[offset:], nil
}
