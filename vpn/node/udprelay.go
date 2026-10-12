package vpnnode

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	tailcat "github.com/tailscale/tailcat"

	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/stats"
)

// EncodeUDPTarget 把一个目标地址编码成 UDP 流的**一次性**目标头。
//
// 目标必须是字面 loopback（与 TCP 路径的内层 CONNECT 是同一条契约）：
// 与 TCP 路径不同，对端面的 UDP 不能复用 SOCKS5 的 ASSOCIATE（那条路径会把中继
// socket 绑到对端的 tailcat ULA 上，宿主没有这个地址，必然失败），因此由本包
// 定义这个极简头——第一个数据报携带它，其后全是原始载荷。
//
// 用 host:port 文本而不是 SOCKS5 的 ATYP 结构：两端都是本实现，文本形式让排障
// （抓包、日志）时一眼可读，而长度前缀保证了解码的确定性。
func EncodeUDPTarget(target string) ([]byte, error) {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return nil, fmt.Errorf("vpn: invalid UDP target %q: %w", target, err)
	}
	if _, err := loopbackIP(host); err != nil {
		return nil, err
	}
	if _, err := parsePort(port); err != nil {
		return nil, fmt.Errorf("vpn: invalid UDP target %q: %w", target, err)
	}
	if len(target) > 255 {
		return nil, fmt.Errorf("vpn: UDP target %q is too long", target)
	}
	return append([]byte{byte(len(target))}, target...), nil
}

// DecodeUDPTarget 从数据报的开头解出目标头，返回目标地址与剩余载荷。
//
// 非 loopback 目标在这里被拒绝：这是对端面"不可能成为内网跳板"这条安全边界的
// 唯一关卡（对端面只可能拨自己的 loopback）。
func DecodeUDPTarget(pkt []byte) (target string, payload []byte, err error) {
	if len(pkt) == 0 {
		return "", nil, errors.New("vpn: empty UDP datagram: expected a target header")
	}
	n := int(pkt[0])
	if n == 0 {
		return "", nil, errors.New("vpn: UDP target header is missing")
	}
	if len(pkt) < 1+n {
		return "", nil, fmt.Errorf("vpn: truncated UDP target header: want %d bytes, have %d", n, len(pkt)-1)
	}
	target = string(pkt[1 : 1+n])

	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return "", nil, fmt.Errorf("vpn: invalid UDP target %q: %w", target, err)
	}
	if _, err := loopbackIP(host); err != nil {
		return "", nil, err
	}
	if _, err := parsePort(port); err != nil {
		return "", nil, fmt.Errorf("vpn: invalid UDP target %q: %w", target, err)
	}
	return target, pkt[1+n:], nil
}

// UDPRelay 是对端面的薄 UDP 中继：把隧道里的每条 UDP 流转成到本机 loopback 的
// 一条 UDP 套接字，两个方向都只做原始数据报透传（不重组、不分片）。
//
// 每条隧道 UDP 流对应一个目标：流建立时由第一个数据报的目标头确定，之后不再改变。
// 这与 tailcat 的语义一致（它按"客户端源地址:端口"隔离流），也让对端面无需维护
// 任何跨数据报的状态。
type UDPRelay struct {
	// IdleTimeout 是单条流在无数据往来时可保持的时长。零值取
	// tailcat.DefaultUDPIdleTimeout，与 tailcat 自己回收 UDP 流的节奏一致，避免
	// 我们比它更早掐断或比它更晚释放本地套接字。
	IdleTimeout time.Duration

	// Logf 是可选的 printf 风格日志器，便于测试与复用。
	Logf func(format string, args ...any)

	mu     sync.Mutex
	closed bool
	conns  map[net.Conn]struct{}
	wg     sync.WaitGroup
}

// Serve 在 listener 上接受隧道 UDP 流，直到 listener 被关闭。
//
// 它刻意**不**在返回前等待在飞流：那些流的生命周期由 Close 收尾（Close 会先关闭
// 它们的套接字再等待），而 Serve 的返回只能由调用方关闭 listener 触发。若在这里
// 等待，调用方"先关 listener、再 Close"的顺序就会自锁到空闲超时。
func (r *UDPRelay) Serve(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) || r.isClosed() {
				return nil
			}
			return err
		}
		if !r.start(conn) {
			_ = conn.Close()
			continue
		}
		stats.RecordVPNPeerFaceStream()
	}
}

// start 把一条隧道流登记为在飞并启动它的处理 goroutine；返回 false 表示中继已
// 关闭，调用方应当直接关闭这条流。
//
// 登记与启动必须在**同一把锁内**完成，而且必须用 wg.Go（等价于 Add(1) + go）：
// Close 会先置 closed、再关闭已登记的流、最后 wg.Wait()。如果 Add 落在锁外，
// 就可能出现"Close 已取完快照并开始 Wait（此时计数为 0），Serve 才 Add(1)"这种
// 对 WaitGroup 的非法复用——那会 panic，或者让 Close 提前返回、留下无人收尾的流。
func (r *UDPRelay) start(conn net.Conn) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return false
	}
	if r.conns == nil {
		r.conns = make(map[net.Conn]struct{})
	}
	r.conns[conn] = struct{}{}
	r.wg.Go(func() {
		defer r.forget(conn)
		r.handle(conn)
	})
	return true
}

// Close 停止接受新流并关闭全部在飞流。它不关闭 Serve 收到的 listener（那是调用方
// 的），因此 Serve 的返回由调用方关闭 listener 触发。
func (r *UDPRelay) Close() {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return
	}
	r.closed = true
	conns := make([]net.Conn, 0, len(r.conns))
	for c := range r.conns {
		conns = append(conns, c)
	}
	r.mu.Unlock()

	for _, c := range conns {
		_ = c.Close()
	}
	r.wg.Wait()
}

func (r *UDPRelay) isClosed() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.closed
}

func (r *UDPRelay) forget(c net.Conn) {
	r.mu.Lock()
	delete(r.conns, c)
	r.mu.Unlock()
}

func (r *UDPRelay) idleTimeout() time.Duration {
	if r.IdleTimeout > 0 {
		return r.IdleTimeout
	}
	return tailcat.DefaultUDPIdleTimeout
}

func (r *UDPRelay) logf(format string, args ...any) {
	if r.Logf != nil {
		r.Logf(format, args...)
		return
	}
	log.Debug("[VPN] udp relay: " + fmt.Sprintf(format, args...))
}

// handle 处理一条隧道 UDP 流：首个数据报确定目标，随后双向透传原始数据报。
func (r *UDPRelay) handle(tunnel net.Conn) {
	defer tunnel.Close() //nolint:errcheck

	idle := r.idleTimeout()
	_ = tunnel.SetReadDeadline(time.Now().Add(idle))

	buf := make([]byte, tailcat.MaxUDPPayload)
	n, err := tunnel.Read(buf)
	if err != nil {
		r.logf("read target header: %v", err)
		return
	}
	target, payload, err := DecodeUDPTarget(buf[:n])
	if err != nil {
		// 只记地址不记内容：这里可能承载用户数据。
		r.logf("rejected flow: %v", err)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), idle)
	defer cancel()
	local, err := (&net.Dialer{}).DialContext(ctx, "udp", target)
	if err != nil {
		r.logf("dial %s: %v", target, err)
		return
	}
	defer local.Close() //nolint:errcheck

	if len(payload) > 0 {
		if _, err := local.Write(payload); err != nil {
			r.logf("forward first payload to %s: %v", target, err)
			return
		}
	}

	var wg sync.WaitGroup
	// 两个方向共用一个"最近活动"时间戳：UDP 流是双向可用的，单向流量
	//（例如只上报、不回收的 syslog）也必须活到真正的空闲为止，因此空闲的判据是
	// **任一方向**有数据往来，而不是每个方向各自计时。
	activity := &flowActivity{}
	activity.touch()
	// 任一方向结束就拆掉整条流：UDP 没有半关闭语义，让另一侧的 Read 立刻失败，
	// 比等它自己的期限到期更符合"这条流已经没了"的事实（也让 Stop 能及时收尾）。
	var once sync.Once
	stop := func() {
		once.Do(func() {
			_ = local.Close()
			_ = tunnel.Close()
		})
	}
	// 隧道 -> 本地目标：原始数据报，不再有目标头。
	wg.Go(func() {
		defer stop()
		r.copyDatagrams(local, tunnel, idle, activity)
	})
	// 本地目标 -> 隧道：原始数据报。
	wg.Go(func() {
		defer stop()
		r.copyDatagrams(tunnel, local, idle, activity)
	})
	wg.Wait()
}

// udpIdleCheckInterval 是空闲判定的**最大**轮询粒度。
//
// 每个方向只能给自己的 conn 设读期限，因此当一个方向阻塞在读、另一个方向还在传
// 数据时，前者的期限不会自动后移。把期限压到这个粒度并周期性复核"整条流是否真的
// 空闲"，就能同时满足两件事：单向流量不被误杀，而双向都停下来的流一定在 idle 之后
// 被回收。
//
// 实际轮询间隔取 min(这个值, idle)：否则一个比 15s 更短的 idle 会失效（流要等到
// 下一轮 15s 才被判定为空闲），回收时刻会比用户配置晚最多一个数量级。
const udpIdleCheckInterval = 15 * time.Second

// flowActivity 记录一条 UDP 流最近一次有数据往来的时间。
type flowActivity struct {
	last atomic.Int64 // UnixNano
}

func (a *flowActivity) touch() { a.last.Store(time.Now().UnixNano()) }

// expired 报告这条流是否已经空闲了至少 idle。
func (a *flowActivity) expired(idle time.Duration) bool {
	return time.Since(time.Unix(0, a.last.Load())) >= idle
}

// copyDatagrams 把 src 的数据报原样写到 dst，并在**整条流**空闲超时后结束。
//
// 缓冲区按 UDP 单包上限分配，超出部分被丢弃——tailcat 隧道本身就只承载
// MaxUDPPayload 以内的一包。
func (r *UDPRelay) copyDatagrams(dst, src net.Conn, idle time.Duration, activity *flowActivity) {
	buf := make([]byte, tailcat.MaxUDPPayload)
	poll := min(idle, udpIdleCheckInterval)
	for {
		_ = src.SetReadDeadline(time.Now().Add(poll))
		n, err := src.Read(buf)
		if n > 0 {
			activity.touch()
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err == nil {
			continue
		}
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			if activity.expired(idle) {
				return
			}
			// 另一个方向还有流量：这不是空闲，继续等。
			continue
		}
		return
	}
}

// loopbackIP 解析并校验 host 是字面 loopback 地址。
//
// 域名（包括 "localhost"）一律拒绝：这是刻意的——对端面不允许任何形式的名字解析，
// 因此"对端面只可能拨自己的 loopback"这条性质不依赖 DNS 是否可信。
func loopbackIP(host string) (netip.Addr, error) {
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("vpn: peer face only accepts literal loopback targets, got %q "+
			"(hostnames such as \"localhost\" are rejected on purpose)", host)
	}
	ip = ip.Unmap()
	if !ip.IsLoopback() {
		return netip.Addr{}, fmt.Errorf("vpn: peer face rejected non-loopback target %q", host)
	}
	return ip, nil
}

// parsePort 把端口文本解析成 1..65535 的数字。
//
// 刻意只接受数字，不用 net.LookupPort：服务名（如 "http"）虽然能被解析成端口，但它
// 引入了一份宿主 /etc/services 依赖——同一个配置在不同机器上会拨到不同端口，而这条
// 路径的目标从来都是本实现自己生成的。
func parsePort(port string) (int, error) {
	n, err := strconv.Atoi(port)
	if err != nil {
		return 0, fmt.Errorf("port %q is not a number", port)
	}
	if n <= 0 || n > 65535 {
		return 0, fmt.Errorf("port %q out of range", port)
	}
	return n, nil
}
