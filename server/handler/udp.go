package handler

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/crypto"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/protocol"
	"github.com/nange/easyss/v3/server/nextproxy"
	"github.com/nange/easyss/v3/shaper"
	"github.com/nange/easyss/v3/util"
	"github.com/nange/easyss/v3/util/bytespool"
)

const udpBufSize = protocol.MaxUDPDataSize

type udpHandler struct {
	idleTimeout time.Duration
	// nextProxy 在这里单独保存（而不仅存在于 dial 内部），因为只有 UDP
	// 会在数据报流上用它进行 DNS 应答学习，与当前目标是否经由它路由无关。
	nextProxy *nextproxy.NextProxy
	dial      dialer
}

// newUDPHandler 用给定的空闲超时和基础超时创建 udpHandler。
// 与 newTCPHandler 一样，拨号超时通过 config.DialTimeout 派生
// （base/3，限制在 [3s, 15s]），而不是复用长得多的空闲超时。
func newUDPHandler(idleTimeout, timeout time.Duration, np *nextproxy.NextProxy) *udpHandler {
	if idleTimeout <= 0 {
		idleTimeout = config.DefaultUDPIdleTimeout
	}
	if timeout <= 0 {
		timeout = time.Duration(config.DefaultTimeout) * time.Second
	}
	directDialer := outboundDialer(config.DialTimeout(timeout), 0)
	h := &udpHandler{idleTimeout: idleTimeout, nextProxy: np}
	h.dial = dialer{
		nextProxy: np,
		shouldProxy: func(target string) bool {
			return np.EnableUDP() && np.ShouldProxy(target)
		},
		direct: func(ctx context.Context, network, target string) (net.Conn, error) {
			return dialOutbound(ctx, directDialer, network, target)
		},
	}
	return h
}

// Handle 在客户端流与目标之间中继 UDP 数据报，并以结构化结果返回已推送的
// 载荷字节数与远端地址（日志由 serveSession 的唯一出口记录）。
// cancelRead 在 handler 终止（空闲超时/错误/FIN）时被调用：
// 它会解除可能正阻塞在读取客户端请求体上的帧读取 goroutine，
// 从而在 ServeHTTP 返回后不会有 goroutine 残留。
func (h *udpHandler) Handle(ctx context.Context, dr *crypto.DecryptedReader, s2c shaper.Shaper, target string, cancelRead func()) streamResult {
	log.Debug("[UDP] handler starting", "target", target)

	conn, remote, err := h.dial.dialTarget(ctx, "udp", target)
	if err != nil {
		log.Error("[UDP] dial target failed", "target", target, "err", err)
		sendRST(s2c)
		return streamResult{Err: err}
	}
	var dnsDetected atomic.Bool
	var dnsChecked atomic.Bool

	// transferred 由读取侧累加、主 goroutine 在返回前读取：它是两条 goroutine
	// 之间唯一共享的可变计数（Phase 2 会把整个会话收进一个值对象）。
	var transferred atomic.Int64
	done := make(chan struct{})
	closeDone := sync.OnceFunc(func() {
		close(done)
		if cancelRead != nil {
			cancelRead()
		}
	})
	defer closeDone()
	defer conn.Close() //nolint:errcheck
	errCh := make(chan error, 1)
	go func() {
		errCh <- h.readFromTarget(conn, s2c, done, &dnsDetected, &transferred, remote)
	}()
	frameCh := make(chan udpFrameResult, 1)
	go func() {
		for {
			frame, err := dr.ReadFrame()
			select {
			case frameCh <- udpFrameResult{frame: frame, err: err}:
			case <-done:
				return
			}
			if err != nil {
				return
			}
		}
	}()
	timer := time.NewTimer(h.idleTimeout)
	defer timer.Stop()

	for {
		select {
		case err := <-errCh:
			closeDone()
			if errors.Is(err, io.EOF) {
				return streamResult{Remote: remote, Bytes: transferred.Load()}
			}
			sendRST(s2c)
			return streamResult{Remote: remote, Bytes: transferred.Load(), Err: err}
		case res := <-frameCh:
			if res.err != nil {
				closeDone()
				sendRST(s2c)
				return streamResult{Remote: remote, Bytes: transferred.Load(), Err: res.err}
			}
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(h.idleTimeout)

			// DNS 查询检测（仅在第一个 DATAGRAM 帧上）
			if !dnsChecked.Load() && h.nextProxy != nil &&
				res.frame.Type == protocol.FrameDATAGRAM && len(res.frame.Payload) > 0 {
				msg := &dns.Msg{}
				if err := msg.Unpack(res.frame.Payload); err == nil && util.IsDNSRequest(msg) {
					dnsDetected.Store(true)
					domain := strings.TrimSuffix(msg.Question[0].Name, ".")
					viaNextProxy := h.nextProxy.IsCustomDomain(domain)
					log.Info("[UDP_DNS]", "domain", domain, "target", target, "via_next_proxy", viaNextProxy)
				}
				dnsChecked.Store(true)
			}

			if err := h.handleClientFrame(conn, res.frame); err != nil {
				closeDone()
				sendRST(s2c)
				return streamResult{Remote: remote, Bytes: transferred.Load(), Err: err}
			}
			if res.frame.Type == protocol.FrameFIN || res.frame.Type == protocol.FrameRST {
				closeDone()
				return streamResult{Remote: remote, Bytes: transferred.Load()}
			}
		case <-timer.C:
			closeDone()
			log.Debug("[UDP] idle timeout", "target", target, "timeout", h.idleTimeout)
			return streamResult{Remote: remote, Bytes: transferred.Load(), TimedOut: true}
		}
	}
}

type udpFrameResult struct {
	frame protocol.Frame
	err   error
}

func (h *udpHandler) handleClientFrame(conn net.Conn, frame protocol.Frame) error {
	switch frame.Type {
	case protocol.FrameDATAGRAM:
		if len(frame.Payload) > 0 {
			_, err := conn.Write(frame.Payload)
			return err
		}
	case protocol.FrameFIN, protocol.FrameRST, protocol.FramePADDING, protocol.FrameCOVER:
		return nil
	}
	return nil
}

func (h *udpHandler) readFromTarget(conn net.Conn, s2c shaper.Shaper, done <-chan struct{}, dnsDetected *atomic.Bool, transferred *atomic.Int64, remote string) error {
	buf := bytespool.Get(udpBufSize)
	defer bytespool.MustPut(buf)
	for {
		select {
		case <-done:
			return io.EOF
		default:
		}

		_ = conn.SetReadDeadline(time.Now().Add(h.idleTimeout))
		n, err := conn.Read(buf)
		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				return io.EOF
			}
			if errors.Is(err, net.ErrClosed) {
				return io.EOF
			}
			log.Error("[UDP] read from target failed", "target", remote, "err", err)
			return err
		}
		if n > 0 {
			// 拦截 DNS 应答以进行动态 IP 学习
			if dnsDetected.Load() && h.nextProxy != nil {
				msg := &dns.Msg{}
				if err := msg.Unpack(buf[:n]); err == nil && util.IsDNSResponse(msg) {
					domain := strings.TrimSuffix(msg.Question[0].Name, ".")
					if h.nextProxy.IsCustomDomain(domain) {
						util.ForEachDNSAnswer(msg, func(kind, value string) {
							if kind == "CNAME" {
								h.nextProxy.AddDomain(value)
								return
							}
							h.nextProxy.AddIP(value)
						})
					}
				}
			}

			frame := protocol.NewFrameDATAGRAM(buf[:n])
			if wErr := s2c.PushFrame(frame); wErr != nil {
				return wErr
			}
			transferred.Add(int64(n))
		}
	}
}
