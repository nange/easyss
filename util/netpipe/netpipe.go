// Package netpipe 提供 net.Pipe 的**带缓冲**替代品：写入立即进入环形缓冲并返回，
// 因此写方不必等对端把数据读走。它是 runner/derpdialer.go 把 tailcat 的 DERP
// 连接送进 easyss 隧道时用的那一层缓冲。
//
// 为什么需要它：DERP 连接是 tailscale 数据面的一部分，而 tailscale 假设"DERP 连接
// 是真实 TCP 套接字、有几 MB 内核缓冲"。换成 net.Pipe 之后这个假设不成立——每个包
// 的写入都必须等中继 goroutine 读走，而中继 goroutine 会在隧道写阻塞时停住，于是
// 背压直接打在 magicsock 那个 32 深、满了丢最旧的写队列上。实测（单程 60ms、
// 内层 RTT 240ms、中继队列 1024 帧）：DERP 连接是普通 TCP 套接字时 2929 KB/s，
// 换成无缓冲 net.Pipe 只剩 175 KB/s——两个数量级不是来自带宽，而是来自"没有缓冲"。
//
// 为什么不用 github.com/smallnest/ringbuffer 自带的阻塞模式：它的超时是**每次等待
// 的预算**（WithReadTimeout/WithWriteTimeout），在 waitRead/waitWrite 里被定时器
// 引用一次就固定，因此已经阻塞的调用无法被后设的 deadline 打断；而且默认"超时即
// 关闭缓冲区"，一个 set-and-forget 的 deadline 就能把连接永久废掉。net.Conn 的契约
// 是"deadline 是绝对时间、可随时改写、改写对阻塞中的操作立即生效"（标准库的
// net/http 就靠"把 deadline 设成过去"来取消请求），所以本包只用它做**存储**：
// 读写走非阻塞 API（Read/Write 在非阻塞模式下返回 ErrIsEmpty/ErrIsFull），等待与
// deadline 由本包自己的 select 循环实现。
//
// 与 net.Pipe 的语义差异（刻意的）：
//
//   - 写不阻塞到对端读走，而是阻塞到缓冲区满（异步、带缓冲）——这正是本包存在的理由；
//   - 超时返回 os.ErrDeadlineExceeded（满足 net.Error 且 errors.Is 可用），而不是
//     库的 context.DeadlineExceeded 或自定义 error；
//   - 对端 Close 后：本端 Read 返回 io.EOF、Write 返回 io.ErrClosedPipe（与 net.Pipe
//     一致）；本端 Close 后：本端读写都返回 net.ErrClosed 或 io.ErrClosedPipe。
package netpipe

import (
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/smallnest/ringbuffer"
)

// Pipe 返回一对互为对端的 net.Conn：一端写入的数据可以从另一端读出，每个方向各有
// size 字节缓冲。size <= 0 时取 defaultSize。
//
// 两个端各自只允许一个并发读者与一个并发写者（net.Conn 的常规约定）；Close 与
// Set*Deadline 可以来自任意 goroutine。
func Pipe(size int) (net.Conn, net.Conn) {
	if size <= 0 {
		size = defaultSize
	}
	ab := newBuffer(size) // a 写、b 读
	ba := newBuffer(size) // b 写、a 读
	return &conn{rd: ba, wr: ab, closedCh: make(chan struct{})},
		&conn{rd: ab, wr: ba, closedCh: make(chan struct{})}
}

// defaultSize 是未指定缓冲大小时的默认值：256KB/方向。它与"经中继的单流吞吐 ≈
// 缓冲 / RTT"这条关系直接相关（DERP 路径的墙上窗口就是各段缓冲之和），因此不能太小；
// 又因为它是每个 DERP 连接各一份（每对端一条连接）、且在链路饱和时会贡献排队延迟，
// 所以也不宜无脑放大。调用方（runner/derpdialer.go）用的是共享配置里的常量。
const defaultSize = 256 << 10

// buffer 是一个单向缓冲：一端写、另一端读。
//
// data/space 是本包自己的"状态可能变了"信号（容量 1、可合并），用来在没有库内
// 条件变量可用的情况下唤醒等待者：
//
//   - data：写方通知读方（有数据了，或写侧已关闭）；
//   - space：读方通知写方（腾出空间了，或读侧已关闭）。
//
// 两个方向分成两个通道是有意的：只有一个通道时，读者可能把本该唤醒写者的信号消费掉，
// 于是写者在缓冲区明明有空间的情况下一直睡着（丢唤醒）。
type buffer struct {
	rb    *ringbuffer.RingBuffer
	data  chan struct{}
	space chan struct{}
}

func newBuffer(size int) *buffer {
	return &buffer{
		rb:    ringbuffer.New(size),
		data:  make(chan struct{}, 1),
		space: make(chan struct{}, 1),
	}
}

func signal(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default: // 已有一个待处理信号：合并
	}
}

// conn 是 Pipe 返回的一端：rd 是"对端写进来"的缓冲，wr 是"本端写出去"的缓冲。
type conn struct {
	rd *buffer
	wr *buffer

	closedCh chan struct{} // Close 时关闭，唤醒本端所有等待者
	closed   atomic.Bool

	dlMu      sync.Mutex
	rdl, wdl  time.Time
	dlChanged chan struct{} // 容量 1：deadline 被改写时唤醒等待者重新计算
	dlOnce    sync.Once

	closeOnce sync.Once
}

func (c *conn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for {
		n, err := c.rd.rb.Read(p)
		if n > 0 {
			// 腾出了空间：唤醒对端的写方。即使同时带着 io.EOF，也要先把数据交付
			// （io.Reader 契约：调用方必须先处理 n > 0）。
			signal(c.rd.space)
			return n, nil
		}
		switch {
		case errors.Is(err, ringbuffer.ErrIsEmpty), err == nil:
			if werr := c.wait(c.rd.data, c.readDeadline); werr != nil {
				return 0, werr
			}
		case errors.Is(err, io.EOF):
			return 0, io.EOF
		default:
			// 本端已 Close（读缓冲上的 sticky error）、或库内部错误。
			return 0, err
		}
	}
}

func (c *conn) Write(p []byte) (int, error) {
	// 库拒绝"单次写入大于整个缓冲区"的调用（ErrTooMuchDataToWrite），因此这里必须
	// 自己按容量切片：net.Conn 的写入不限制大小（TLS 记录、中继那侧 31KB 的读都会
	// 走这里），分片之后每一次尝试要么写入、要么在 ErrIsFull 上等空间。
	capacity := c.wr.rb.Capacity()

	total := 0
	for total < len(p) {
		chunk := p[total:]
		if len(chunk) > capacity {
			chunk = chunk[:capacity]
		}

		n, err := c.wr.rb.Write(chunk)
		if n > 0 {
			total += n
			signal(c.wr.data) // 通知对端的读方
		}
		if total == len(p) {
			return total, nil
		}
		switch {
		case errors.Is(err, ringbuffer.ErrIsFull),
			errors.Is(err, ringbuffer.ErrTooMuchDataToWrite),
			err == nil:
			// 空间不足。库有两个不同的错误：缓冲已满时报 ErrIsFull，而"剩余空间
			// 小于这次写入"时报 ErrTooMuchDataToWrite（同时已经写进去一部分）。
			// 两者对调用方是同一件事：等对端读走再继续。
			if werr := c.wait(c.wr.space, c.writeDeadline); werr != nil {
				return total, werr
			}
		case errors.Is(err, io.EOF):
			// 库把"写侧已关闭"记成 io.EOF（CloseWriter 的产物）时，net.Conn 的
			// 语义是 io.ErrClosedPipe，翻译过来以免调用方误判为流正常结束。
			return total, io.ErrClosedPipe
		default:
			return total, err
		}
	}
	return total, nil
}

// Close 关闭本端：对端的读随后得到 io.EOF，对端的写随后得到 io.ErrClosedPipe，
// 本端自己的读写也会以 net.ErrClosed / io.ErrClosedPipe 失败。幂等。
func (c *conn) Close() error {
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		close(c.closedCh) // 唤醒本端等待者

		// 对端方向一：本端不再写 → 对端读到 EOF。
		c.wr.rb.CloseWriter()
		signal(c.wr.data)
		// 对端方向二：本端不再读 → 对端写失败。
		c.rd.rb.CloseWithError(io.ErrClosedPipe)
		signal(c.rd.space)
	})
	return nil
}

func (c *conn) LocalAddr() net.Addr  { return pipeAddr{} }
func (c *conn) RemoteAddr() net.Addr { return pipeAddr{} }

func (c *conn) SetDeadline(t time.Time) error {
	_ = c.SetReadDeadline(t)
	return c.SetWriteDeadline(t)
}

func (c *conn) SetReadDeadline(t time.Time) error {
	c.dlMu.Lock()
	c.rdl = t
	c.dlMu.Unlock()
	c.signalDeadlineChanged()
	return nil
}

func (c *conn) SetWriteDeadline(t time.Time) error {
	c.dlMu.Lock()
	c.wdl = t
	c.dlMu.Unlock()
	c.signalDeadlineChanged()
	return nil
}

func (c *conn) readDeadline() time.Time {
	c.dlMu.Lock()
	defer c.dlMu.Unlock()
	return c.rdl
}

func (c *conn) writeDeadline() time.Time {
	c.dlMu.Lock()
	defer c.dlMu.Unlock()
	return c.wdl
}

// signalDeadlineChanged 唤醒所有正在等待的读写方，使其重新计算 deadline。
//
// 这是"把 deadline 设成过去"能当场打断阻塞中的操作的原因；库自带的阻塞模式做不到
// 这一点（它的超时在等待开始时就被定时器引用固定了）。
func (c *conn) signalDeadlineChanged() {
	c.dlOnce.Do(func() { c.dlChanged = make(chan struct{}, 1) })
	signal(c.dlChanged)
}

// wait 阻塞直到 ch 收到信号、deadline 到点，或本端被关闭。
// 返回 nil 表示状态可能变了（调用方应当重试操作）；返回非 nil 是应当直接交给调用方
// 的错误。
func (c *conn) wait(ch <-chan struct{}, deadline func() time.Time) error {
	for {
		if c.closed.Load() {
			return net.ErrClosed
		}
		dl := deadline()
		if !dl.IsZero() && !time.Now().Before(dl) {
			return os.ErrDeadlineExceeded
		}

		var timerC <-chan time.Time
		var timer *time.Timer
		if !dl.IsZero() {
			timer = time.NewTimer(time.Until(dl))
			timerC = timer.C
		} else {
			c.dlOnce.Do(func() { c.dlChanged = make(chan struct{}, 1) })
		}

		// dlChanged 可能尚未初始化（从未设置过 deadline），此时读 nil 通道会永久阻塞，
		// 正好符合"没有 deadline 就没有这条唤醒路径"的语义。
		var dlChanged <-chan struct{}
		if c.dlChanged != nil {
			dlChanged = c.dlChanged
		}

		select {
		case <-ch:
			stopTimer(timer)
			return nil
		case <-timerC:
			stopTimer(timer)
			// 定时器到点与 deadline 被改写到更晚可能同时发生：重新判断一次，
			// 不要把"已被推迟的 deadline"报成超时。
			if cur := deadline(); cur.IsZero() || time.Now().Before(cur) {
				continue
			}
			return os.ErrDeadlineExceeded
		case <-dlChanged:
			stopTimer(timer)
		case <-c.closedCh:
			stopTimer(timer)
			return net.ErrClosed
		}
	}
}

func stopTimer(t *time.Timer) {
	if t != nil {
		t.Stop()
	}
}

// pipeAddr 是本包连接上报的地址。它不是 host:port，因此依赖地址解析的调用方
// （例如 derphttp 把 LocalAddr 解析成 netip.AddrPort）会得到"解析失败"这一既有行为，
// 与 net.Pipe 的 "pipe" 相同。
type pipeAddr struct{}

func (pipeAddr) Network() string { return "netpipe" }
func (pipeAddr) String() string  { return "netpipe" }

var (
	_ net.Conn = (*conn)(nil)
	_          = signal
)
