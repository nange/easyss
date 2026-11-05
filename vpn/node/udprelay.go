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

// EncodeUDPTarget 把目标地址编码成 UDP 流的一次性目标头：首字节长度 + host:port 文本。
// 目标必须是字面 loopback（与 TCP 路径内层 CONNECT 同一条契约）；对端面不能复用 SOCKS5
// ASSOCIATE——那条路径会把中继 socket 绑到对端没有的 tailcat ULA 上。
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

// DecodeUDPTarget 从数据报开头解出目标头，返回目标地址与剩余载荷。
// 非 loopback 目标必须在这里拒绝：这是对端面"不可能成为内网跳板"的唯一关卡。
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

// maxUDPTargetHeader 是目标头的最大长度：1 字节长度前缀 + 最多 255 字节的目标文本。
const maxUDPTargetHeader = 1 + 255

// maxFirstDatagram 是首包的上限：目标头与首段载荷放在同一条数据报里（见 EncodeUDPTarget），
// 因此它比单包上限多出一个目标头的空间，否则文档允许的 1232 字节载荷会被剪掉尾巴。
const maxFirstDatagram = maxUDPTargetHeader + tailcat.MaxUDPPayload

// UDPRelay 是对端面的薄 UDP 中继：把隧道里的每条 UDP 流转成到本机 loopback 的
// 一条 UDP 套接字，两个方向都只透传原始数据报。
// 每条隧道 UDP 流对应一个目标，由第一个数据报的目标头确定后不再改变（tailcat 按源地址:端口隔离流）。
type UDPRelay struct {
	// IdleTimeout 是单条流在无数据往来时可保持的时长。零值取
	// tailcat.DefaultUDPIdleTimeout，与 tailcat 自己回收 UDP 流的节奏一致，避免
	// 我们比它更早掐断或比它更晚释放本地套接字。
	IdleTimeout time.Duration

	Logf func(format string, args ...any)

	mu     sync.Mutex
	closed bool
	conns  map[net.Conn]struct{}
	wg     sync.WaitGroup
}

// Serve 在 listener 上接受隧道 UDP 流，直到 listener 被关闭。
// 返回前**不**等待在飞流（那是 Close 的职责）：在这里等会让"先关 listener、再 Close"自锁到空闲超时。
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

// start 把一条隧道流登记为在飞并启动处理 goroutine；返回 false 表示中继已关闭。
// 登记与 wg.Go 必须在同一把锁内完成：Close 先置 closed、再关已登记的流、最后 wg.Wait()，
// Add 落在锁外会让 WaitGroup 在 Wait 之后被复用（panic 或留下无人收尾的流）。
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

func (r *UDPRelay) handle(tunnel net.Conn) {
	defer tunnel.Close() //nolint:errcheck

	idle := r.idleTimeout()
	_ = tunnel.SetReadDeadline(time.Now().Add(idle))

	// 多读一字节用于识别截断：Read 在缓冲区处剪断数据报且不报错，n 超过上限说明这条
	// 首包已经被剪短，转发出去就是静默的数据损坏。
	buf := make([]byte, maxFirstDatagram+1)
	n, err := tunnel.Read(buf)
	if err != nil {
		r.logf("read target header: %v", err)
		return
	}
	if n > maxFirstDatagram {
		r.logf("dropped an oversized first datagram: limit %d bytes", maxFirstDatagram)
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

// udpIdleCheckInterval 是空闲判定的**最大**轮询粒度，实际间隔取 min(这个值, idle)。
// 每方向只能给自己的 conn 设读期限，因此按这个粒度复核整条流：单向流量不被误杀，
// 双向都停下来的流在 idle 后回收；取 min 是为了短 idle 不被拖到下一轮。
const udpIdleCheckInterval = 15 * time.Second

type flowActivity struct {
	last atomic.Int64 // UnixNano
}

func (a *flowActivity) touch() { a.last.Store(time.Now().UnixNano()) }

func (a *flowActivity) expired(idle time.Duration) bool {
	return time.Since(time.Unix(0, a.last.Load())) >= idle
}

// copyDatagrams 把 src 的数据报原样写到 dst，并在**整条流**空闲超时后结束。
// 缓冲区按 tailcat 的 UDP 单包上限分配，多出的一字节用于识别"读满即被截断"。
func (r *UDPRelay) copyDatagrams(dst, src net.Conn, idle time.Duration, activity *flowActivity) {
	buf := make([]byte, tailcat.MaxUDPPayload+1)
	poll := min(idle, udpIdleCheckInterval)
	for {
		_ = src.SetReadDeadline(time.Now().Add(poll))
		n, err := src.Read(buf)
		if n > 0 {
			activity.touch()
			switch {
			case n > tailcat.MaxUDPPayload:
				// 超出隧道的单包上限：Read 已经把数据报剪到缓冲区长度，转发剪短的载荷
				// 比丢弃更难排查（应用会收到半截数据报且两端都认为成功）。
				r.logf("dropped an oversized datagram: limit %d bytes", tailcat.MaxUDPPayload)
			default:
				if _, werr := dst.Write(buf[:n]); werr != nil {
					return
				}
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

// loopbackIP 解析并校验 host 是字面 loopback 地址；域名（含 "localhost"）一律拒绝。
// 对端面不允许任何形式的名字解析，"只可能拨自己的 loopback"因此不依赖 DNS 是否可信。
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
// 只接受数字：net.LookupPort 会用宿主的 /etc/services，同一配置在不同机器上会拨到不同端口。
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
