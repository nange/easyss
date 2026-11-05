// Package netpipe 提供 net.Pipe 的带缓冲替代品：写入进入缓冲后立即返回。tailcat
// 假设 DERP 连接是有内核缓冲的真实 TCP，无缓冲的 net.Pipe 会把背压直接打在
// magicsock 32 深、丢最旧的写队列上。DERP 拨号器传入 config.DERPPipeBufferSize。
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

// Pipe 返回一对互为对端的 net.Conn，每个方向各有 size 字节缓冲（size <= 0 取
// defaultSize）。每端只允许一个并发读者与一个并发写者；Close 与 Set*Deadline 可
// 来自任意 goroutine。
func Pipe(size int) (net.Conn, net.Conn) {
	if size <= 0 {
		size = defaultSize
	}
	ab := newBuffer(size) // a 写、b 读
	ba := newBuffer(size) // b 写、a 读
	return &conn{rd: ba, wr: ab, closedCh: make(chan struct{})},
		&conn{rd: ab, wr: ba, closedCh: make(chan struct{})}
}

// defaultSize 是未指定缓冲大小时的默认值（256KB/方向）。经中继的单流吞吐 ≈ 缓冲 /
// RTT，但它每个 DERP 连接各一份且饱和时贡献排队延迟；生产路径传入
// config.DERPPipeBufferSize，不要另调。
const defaultSize = 256 << 10

// buffer 是一个单向缓冲：一端写、另一端读。data/space 是容量 1、可合并的"状态可能
// 变了"信号，data 由写方唤醒读方、space 由读方唤醒写方；两个方向必须分开，否则读者
// 可能消费掉本该唤醒写者的信号而丢唤醒。
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
	// 库拒绝单次写入大于整个缓冲区的调用（ErrTooMuchDataToWrite），因此必须按容量
	// 切片：net.Conn 的写入不限制大小，TLS 记录等可能远大于缓冲。
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
			// 缓冲满报 ErrIsFull，"剩余空间小于这次写入"报 ErrTooMuchDataToWrite
			// （已写入一部分）：对调用方是同一件事，等对端读走再继续。
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

// deadline 是绝对时间、可随时改写且对阻塞中的操作立即生效；超时返回
// os.ErrDeadlineExceeded（满足 net.Error），不毒化连接。
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

// 等待中的读写方必须被此调用唤醒，否则 deadline 改写不会生效。
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

// pipeAddr 不是 host:port：依赖地址解析的调用方（如 derphttp 把 LocalAddr 解析成
// netip.AddrPort）会得到解析失败，与 net.Pipe 的 "pipe" 行为相同。
type pipeAddr struct{}

func (pipeAddr) Network() string { return "netpipe" }
func (pipeAddr) String() string  { return "netpipe" }

var (
	_ net.Conn = (*conn)(nil)
	_          = signal
)
