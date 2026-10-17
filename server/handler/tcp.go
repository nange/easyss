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
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/protocol"
	"github.com/nange/easyss/v3/relay"
	"github.com/nange/easyss/v3/server/nextproxy"
	"github.com/nange/easyss/v3/shaper"
	"github.com/nange/easyss/v3/stats"
	"github.com/nange/easyss/v3/util/netbuf"
)

type tcpHandler struct {
	idleTimeout time.Duration
	// dialContext 是仅供测试的直接拨号注入点；生产环境为 nil。
	dialContext func(context.Context, string, string) (net.Conn, error)
	dial        dialer
}

// newTCPHandler 用给定的空闲超时和基础超时创建 tcpHandler。
// 拨号超时通过 config.DialTimeout 派生（base/3，限制在 [3s, 15s]），与客户端
// 共用；KeepAlive 取完整的基础超时，这样长连接流由内核回收，而不会在对端
// 消失后一直半开残留。
func newTCPHandler(idleTimeout, timeout time.Duration, np *nextproxy.NextProxy) *tcpHandler {
	if idleTimeout <= 0 {
		idleTimeout = config.DefaultStreamIdleTimeout
	}
	if timeout <= 0 {
		timeout = time.Duration(config.DefaultTimeout) * time.Second
	}
	directDialer := outboundDialer(config.DialTimeout(timeout), timeout)
	h := &tcpHandler{idleTimeout: idleTimeout}
	h.dial = dialer{
		nextProxy:   np,
		shouldProxy: np.ShouldProxy,
		direct: func(ctx context.Context, network, target string) (net.Conn, error) {
			// 测试注入点：生产环境为 nil。
			if h.dialContext != nil {
				return h.dialContext(ctx, network, target)
			}
			return dialOutbound(ctx, directDialer, network, target)
		},
	}
	return h
}

// Handle 在客户端与目标之间中继 TCP 流，并以结构化结果返回中继字节数与退出
// 原因（由 serveSession 统一记录，handler 自己不再打印"流已结束"）。
// cancelRead 在中继终止（超时/错误/完成）时被调用；
// 它会解除可能正阻塞在读取客户端数据（如 HTTP/2 请求体）上的拷贝 goroutine，
// 从而在 handler 返回后不会有 goroutine 残留。
func (h *tcpHandler) Handle(ctx context.Context, dr *crypto.DecryptedReader, s2c shaper.Shaper, target string, cancelRead func()) (out streamResult) {
	log.Info("[TCP_HANDLE] dialing target", "target", target)
	targetConn, remote, err := h.dial.dialTarget(ctx, "tcp", target)
	if err != nil {
		log.Error("[TCP_HANDLE] dial failed", "target", target, "err", err)
		sendRST(s2c)
		return streamResult{Err: err}
	}
	defer targetConn.Close() //nolint:errcheck
	log.Info("[TCP_HANDLE] target connected", "target", target, "remote", remote)
	m := stats.NewStreamMeter("tcp_handle", target)
	// 先取字节数再关闭 meter，使 handler 返回时 out.Bytes 已经是最终值
	// （defer 按后进先出执行，这里注册的清理在返回前完成）。
	defer func() {
		out.Bytes = m.Bytes()
		m.Close()
	}()

	// 中继的 onClose 既要解除客户端读取器阻塞（cancelRead），
	// 也要关闭目标连接，因此这里把通用的 CloseBoth 与该回调组合在一起。
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
		out.Err = fmt.Errorf("tcp stream idle timeout after %v", h.idleTimeout)
	} else {
		out.Err = result.Err
	}
	if out.needsRST() {
		sendRST(s2c)
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
			// FIN 是终止帧：客户端在它之后不会再发送任何帧
			// （客户端的 copyLocalToRemote 在 flush FIN 后立即返回），
			// 因此停止读取，而不是一直阻塞在 ReadFrame 上直到中继空闲超时。
			// 中继仍会等待 target->client 方向，其空闲计时器仍然限定
			// 流的生命周期。
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
	// 读缓冲按需增长：流的起点只占 protocol.MinRecordBufferSize (4KB)，读满一档
	// 才升一档，上限是 config.ServerTCPStreamBufferSize。注意该常量会被 netbuf
	// 向上取到池的 2 的幂档位（31744 → 32768），因此满档时是 1 帧/记录而不是
	// 常量注释里写的 2 帧（2×(32768+3) 放不进一条记录，见
	// protocol.MaxWriteRecordPlaintext）——记录因此约 32KB，落在 64KB 池档位内，
	// 行为无害，只是批处理密度比常量设计时低。此前是无条件借出 31744 字节并钉到
	// 流结束，而 goroutine 大多数时间正阻塞在 src.Read 上持着它，因此空闲流、
	// 心跳流与只传少量数据的流各自白占 31KB——服务端常驻内存因此随峰值并发流数增长。
	//
	// 增长对 TCP 是无损的：缓冲短了只会多几次 Read，数据不会丢，因此这里可以
	// 只按"这次读满了"这一个信号升档（UDP 不能这么做，超长数据报会被静默截断）。
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
			// 增长必须在 PushData 之后：Grow 会把这块缓冲归还池，而 buf[:n]
			// 正指向它。先把数据交给整形器（它在写锁内拷进自己的明文缓冲），
			// 再换档，否则后续写入会落进一块已经入池、可能被别的流取走的缓冲。
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
