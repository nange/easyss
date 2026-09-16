package proxy

import (
	"context"
	"time"

	"github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/log"
)

// WarmUp 在核心启动后立即预热传输层的连接池，使每种流量类别的第一个真实请求
// 不必付出冷启动代价（拨号 + TLS + HTTP/2）。它用对服务器 /v3/probe 端点的真实
// 探测请求来预热连接池——与降级检测器发出的请求相同，只对用户自己的服务器可见。
//
// 调用方在后台运行它（由 runner.Run 派发），因此这里没有抖动、也不会阻塞启动：
// timeout 约束探测阶段，调用方传入 config.WarmUpTimeout。按约定为尽力而为：失败
// 会在此记录日志并返回，由调用方决定如何处理，但启动绝不能依赖预热。返回 nil
// 同样可能意味着预热被跳过（没有代理服务器，或正在关闭）；返回非 nil 也不意味着
// 预热毫无用处：连接可能已建立，只是用于确认它的探测没有及时应答。
func (s *Socks5Server) WarmUp(timeout time.Duration) error {
	if s == nil || s.closing.Load() {
		return nil
	}
	if timeout <= 0 {
		timeout = config.WarmUpTimeout
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	start := time.Now()
	if err := s.handler.Transport().WarmUp(ctx); err != nil {
		log.Warn("[WARMUP] failed",
			"err", err,
			"elapsed_ms", time.Since(start).Milliseconds(),
		)
		return err
	}
	log.Info("[WARMUP] done", "elapsed_ms", time.Since(start).Milliseconds())
	return nil
}
