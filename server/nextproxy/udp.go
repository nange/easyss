package nextproxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/nange/easyss/v3/protocol"
	"github.com/xjasonlyu/tun2socks/v2/transport/socks5"
)

// 本文件实现 next proxy 的 SOCKS5 UDP 转发（RFC 1928 §7 的 UDP ASSOCIATE）。
//
// 协议层（方法协商、可选认证、命令应答解析、数据报封帧）由 tun2socks 的
// transport/socks5 承担：它已经在本进程内被 tun2socks 用来做客户端 UDP
// ASSOCIATE（proxy/socks5.DialUDP），因此两条路径对上游说的是同一套字节。
// 本文件只保留库不提供、又由本项目约定决定的那部分适配：
//
//   - 关联由一条 TCP 控制连接承载，必须在会话存续期间保持打开（RFC 1928：
//     控制连接终止即关联终止）。库把它表达为 net.PacketConn（每条数据报自带
//     目标地址），而 server/handler 的一条 UDP 会话只关心一个目标，需要的是
//     net.Conn 形态。
//   - 上游关闭控制连接时必须立刻打断数据面，而不是让调用方阻塞到会话空闲超时。
//   - 拨号截止时间只能在握手期间生效，不能泄漏到数据面。
//   - 上游应答通配地址（0.0.0.0:port）时替换为控制连接实际到达的代理地址；
//     应答域名时解析成字面 IP（库的 Addr.UDPAddr 对域名返回 nil）。
//   - 本地绑定地址仅在与控制连接同族时使用。
//   - enable_udp=false 时拒绝建立关联（纵深防御，调用方已门控过一次）。
//
// 这正是 x/net/proxy 的 SOCKS5 拨号器不提供的能力：它只实现 CONNECT，把
// network="udp" 交给它只会得到一次注定失败的 TCP 拨号。
const (
	// udpBufSize 是单条 UDP 数据报的载荷上限。它与 server/handler 的 UDP 会话
	// 共用同一个事实来源（protocol.MaxUDPDataSize），使两个方向的边界一致：
	// 会话收得下的数据报，这里也必须封得出来。
	udpBufSize = protocol.MaxUDPDataSize

	// maxUDPDatagram 是一条 SOCKS5 UDP 数据报的最大线上长度：载荷上限加上
	// 最坏情况的头（RSV/FRAG + ATYP + IPv6 地址 + 端口）。接收缓冲按它分配，
	// 一次即可容纳任何合法数据报。
	maxUDPDatagram = udpBufSize + 3 + 1 + net.IPv6len + 2
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

	// 凭据只在有值时传入：库据此通告单个认证方法（有凭据=用户名/密码，否则
	// 无需认证），与迁移前的 socks5 客户端行为一致，也与 CONNECT 路径同源。
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

	// 目标地址提前解析成 SOCKS5 地址：Write 是逐数据报的热路径，不该在那里
	// 重复解析同一个字符串。解析失败说明调用方给了畸形目标，此时还没有人会
	// 用它，直接回收。
	target := socks5.ParseAddrString(dst)
	if target == nil {
		relay.Close() //nolint:errcheck
		return fail(fmt.Errorf("malformed datagram target %q", dst))
	}

	if !deadline.IsZero() {
		// 握手与关联都已完成，清除拨号截止时间：它的剩余额度不该泄漏到数据面
		// ——一次长会话里的静默期可以远超拨号超时。
		if err := control.SetDeadline(time.Time{}); err != nil {
			relay.Close() //nolint:errcheck
			return fail(err)
		}
	}

	c := &udpAssociateConn{control: control, relay: relay, dst: target}
	// 控制连接是关联的存活信号：上游一旦关闭它，这个关联就不再有效，必须
	// 立即终止本地 socket，而不是让调用方一直阻塞在 Read 上。
	go c.monitorControl()
	return c, nil
}

// resolveRelayAddr 把应答里的 BND.ADDR:BND.PORT 解析成可拨号的 UDP 地址。
// 两种情况需要修正而不能直接用库的 Addr.UDPAddr()：
//
//   - 上游应答通配地址（0.0.0.0:port），表示"就在你连我的这个地址上监听"。
//     0.0.0.0 无法作为发送目标，必须替换成控制连接的对端地址。
//   - 上游应答域名（RFC 1928 允许），而库的 UDPAddr() 对域名返回 nil。
func resolveRelayAddr(bindAddr socks5.Addr, controlRemote net.Addr) (*net.UDPAddr, error) {
	if !bindAddr.Valid() {
		return nil, fmt.Errorf("invalid udp relay address in the associate reply: %#v", []byte(bindAddr))
	}
	if bindAddr[0] == socks5.AtypDomainName {
		// 域名形态：解析成字面 IP，避免每条数据报都依赖一次解析。
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

	// 通配地址：改用控制连接实际到达的代理地址。
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

// splitSocksAddr 取出一个域名字段形态的 SOCKS5 地址的域名与端口。
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
// server/handler 的中继循环不必知道 SOCKS5 数据报封装的存在：它只看到
// "读到一个数据报 / 写入一个数据报"。
//
// Write 按固定的 dst 封帧后发给中继地址，读方向剥掉封装：DNS 应答可能来自与
// 查询目标不同的 IP，而 net.Conn 契约不带来源地址；上层按会话区分目标，来源
// 在这里没有去处。
type udpAssociateConn struct {
	control net.Conn
	relay   *net.UDPConn
	// dst 是本会话经上游转发的目标地址（已解析为 SOCKS5 地址形式）。
	dst socks5.Addr

	closeOnce sync.Once
	// writeMu 串行化发送：udpHandler 只在主 goroutine 里写，但 net.Conn 的
	// 契约不承诺这一点。库的 EncodeUDPPacket 每次返回独立缓冲区，因此这里
	// 不需要为复用而持有共享写缓冲。
	writeMu sync.Mutex
	// readMu 保护 scratch：单次 Read 内完成"收包 → 解封装 → 拷贝给调用方"，
	// 因此不需要把整个读取过程串行化。
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
		c.scratch = make([]byte, maxUDPDatagram)
	}
	n, _, err := c.relay.ReadFromUDP(c.scratch)
	if err != nil {
		return 0, err
	}
	_, payload, err := socks5.DecodeUDPPacket(c.scratch[:n])
	if err != nil {
		// 畸形/分片/无法解析的数据报：按 0 字节读取丢弃，让中继循环继续读
		// 下一条，而不是把一条坏数据报当成会话故障（RFC 1928 允许整条丢弃）。
		return 0, nil
	}
	return copy(b, payload), nil
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
