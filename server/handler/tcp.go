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
	"github.com/nange/easyss/v3/util/bytespool"
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

// Handle 在客户端与目标之间中继 TCP 流。
// cancelRead 在中继终止（超时/错误/完成）时被调用；
// 它会解除可能正阻塞在读取客户端数据（如 HTTP/2 请求体）上的拷贝 goroutine，
// 从而在 handler 返回后不会有 goroutine 残留。
func (h *tcpHandler) Handle(ctx context.Context, dr *crypto.DecryptedReader, s2c shaper.Shaper, target string, cancelRead func()) error {
	log.Info("[TCP_HANDLE] dialing target", "target", target)
	targetConn, remote, err := h.dial.dialTarget(ctx, "tcp", target)
	if err != nil {
		log.Error("[TCP_HANDLE] dial failed", "target", target, "err", err)
		sendRST(s2c)
		return err
	}
	defer targetConn.Close() //nolint:errcheck
	log.Info("[TCP_HANDLE] target connected", "target", target, "remote", remote)
	m := stats.NewStreamMeter("tcp_handle", target)
	defer m.Close()

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
	// 记录流的最终结果（中继字节数和退出原因），这样排查被屏蔽主机时，
	// 连接已建立但后来停滞、被重置或没有任何数据的目标可以直接可见。
	// 客户端正常拆除（RST_STREAM/CANCEL、请求体已被关闭）会命中每个流，
	// 因此这类结果降到 Debug；真正的故障保持 Info。
	transient := isTransientStreamError(result.Err)
	attrs := []any{"target", target, "remote", remote, "bytes", m.Bytes(), "timed_out", result.TimedOut, "transient", transient}
	if result.Err != nil {
		attrs = append(attrs, "err", result.Err.Error())
	}
	if transient {
		log.Debug("[TCP_HANDLE] stream closed", attrs...)
	} else {
		log.Info("[TCP_HANDLE] stream closed", attrs...)
	}
	if result.TimedOut {
		log.Debug("[TCP_HANDLE] idle timeout", "target", target, "timeout", h.idleTimeout)
		sendRST(s2c)
		return fmt.Errorf("tcp stream idle timeout after %v", h.idleTimeout)
	}
	if result.Err != nil {
		sendRST(s2c)
	}
	return result.Err
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
	buf := bytespool.Get(config.ServerTCPStreamBufferSize)
	defer bytespool.MustPut(buf)
	for {
		m.SetState("read_target")
		n, err := src.Read(buf)
		if n > 0 {
			signalActivity()
			m.SetState("write_http2")
			if wErr := s2c.PushData(buf[:n]); wErr != nil {
				return wErr
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
