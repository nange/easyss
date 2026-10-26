package handler

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/crypto"
	"github.com/nange/easyss/v3/protocol"
	"github.com/nange/easyss/v3/relay"
	"github.com/nange/easyss/v3/server/nextproxy"
	"github.com/nange/easyss/v3/shaper"
	"github.com/nange/easyss/v3/stats"
	"github.com/nange/easyss/v3/util/netbuf"
)

type tcpHandler struct {
	idleTimeout time.Duration
	// 仅供测试注入直接拨号。
	dialContext func(context.Context, string, string) (net.Conn, error)
	dial        dialer
}

// 零值已由 config.Timeouts.Normalize 填充；Base 用作 KeepAlive，长连接不会在对端消失后
// 一直半开残留。
func newTCPHandler(timeouts config.Timeouts, np *nextproxy.NextProxy, deps *outboundDeps) *tcpHandler {
	directDialer := outboundDialer(timeouts.Dial, timeouts.Base)
	h := &tcpHandler{idleTimeout: timeouts.StreamIdle}
	h.dial = newDialer(np, np.ShouldProxy, deps)
	h.dial.direct = func(ctx context.Context, network, target string) (net.Conn, error) {
		if h.dialContext != nil {
			return h.dialContext(ctx, network, target)
		}
		return h.dial.outbound(ctx, directDialer, network, target)
	}
	return h
}

// 返回前必须经 cancelRead 解除阻塞在客户端读上的拷贝 goroutine，否则会残留。
// 内部不打印拨号/失败日志，失败阶段由 streamResult 的 err 携带。
func (h *tcpHandler) Handle(ctx context.Context, dr *crypto.DecryptedReader, s2c shaper.Shaper, target string, cancelRead func()) (out streamResult) {
	targetConn, remote, err := h.dial.dialTarget(ctx, "tcp", target)
	if err != nil {
		return streamResult{Err: err}
	}
	defer targetConn.Close() //nolint:errcheck
	m := stats.NewStreamMeter("tcp_handle", target)
	// 后进先出：这里在返回前执行，out.Bytes 因此已是最终值。
	defer func() {
		out.Bytes = m.Bytes()
		m.Close()
	}()

	result := relay.Bidirectional(h.idleTimeout, func() {
		if cancelRead != nil {
			cancelRead()
		}
		_ = targetConn.Close()
	},
		func(signal func()) error { return h.copyFromClient(dr, targetConn, signal) },
		func(signal func()) error { return h.copyFromTarget(targetConn, s2c, signal, m) },
	)
	out.Remote = remote
	out.TimedOut = result.TimedOut
	if result.TimedOut {
		out.Err = fmt.Errorf("%w after %v", errStreamIdleTimeout, h.idleTimeout)
	} else {
		out.Err = result.Err
	}
	return out
}

func (h *tcpHandler) copyFromClient(dr *crypto.DecryptedReader, dst net.Conn, signalActivity func()) error {
	for {
		frame, done, err := nextClientFrame(dr)
		if err != nil {
			return err
		}
		if done {
			if frame.Type == protocol.FrameRST {
				return io.EOF
			}
			signalActivity()
			if cw, ok := dst.(interface{ CloseWrite() error }); ok {
				_ = cw.CloseWrite()
			}
			// FIN 之后客户端不再发帧，直接停止读取而不是阻塞到空闲超时；中继仍等
			// target->client 方向，其空闲计时器仍限定流的生命周期。
			return nil
		}
		signalActivity()
		if len(frame.Payload) > 0 {
			if _, wErr := dst.Write(frame.Payload); wErr != nil {
				return wErr
			}
		}
	}
}

func (h *tcpHandler) copyFromTarget(src net.Conn, s2c shaper.Shaper, signalActivity func(), m *stats.StreamMeter) error {
	// 读缓冲按需增长，起点只占 4KB：无条件借满会让空闲流与心跳流各自白占 31KB。只按"这次
	// 读满了"升档对 TCP 无损（短了只多几次 Read），UDP 不能这样——超长数据报会被静默截断。
	r := netbuf.NewReader(protocol.MinRecordBufferSize, config.ServerTCPStreamBufferSize)
	defer r.Release()

	for {
		m.SetState("read_target")
		buf := r.Buf()
		n, err := src.Read(buf)
		if n > 0 {
			signalActivity()
			m.SetState("write_http2")
			if wErr := s2c.PushData(buf[:n]); wErr != nil {
				return wErr
			}
			// 必须在 PushData 之后：Grow 会把这块缓冲还池，而 buf[:n] 正指向它；先交给整形器
			// （它在写锁内拷进明文缓冲）再换档，否则写入会落进已被别的流取走的缓冲。
			if n == len(buf) {
				r.Grow()
			}
			m.Add(n, "read_target")
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				finFrame := protocol.NewFrameFIN()
				_ = s2c.PushFrame(finFrame)
				_ = s2c.Flush()
				signalActivity()
				return nil
			}
			return err
		}
	}
}
