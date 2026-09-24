package runner

import (
	"context"
	"time"

	sharedconfig "github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/transport"
)

// warmUpTransport 预热传输层的连接池，使每种流量类别的第一个真实请求不必付出
// 冷启动代价（拨号 + TLS + HTTP/2）。它用对服务器 /v3/probe 端点的真实探测请求
// 来预热连接池——与降级检测器发出的请求相同，只对用户自己的服务器可见。
//
// 调用方（dispatchWarmUp）在后台运行它，因此这里没有抖动、也不会阻塞启动：
// timeout 约束探测阶段，调用方传入 config.WarmUpTimeout。按约定为尽力而为：失败
// 会在此记录日志并返回，由调用方决定如何处理，但启动绝不能依赖预热。返回 nil
// 同样可能意味着预热被跳过（没有传输层）；返回非 nil 也不意味着预热毫无用处：
// 连接可能已建立，只是用于确认它的探测没有及时应答。
//
// 它由 runner 持有（而不是代理服务器）：预热是核心的启动编排之一，与本地代理
// 入口无关；"socks_port = 0 就跳过"由派发侧负责（见 dispatchWarmUp）。
func warmUpTransport(tr transport.Transport, timeout time.Duration) error {
	if tr == nil {
		return nil
	}
	if timeout <= 0 {
		timeout = sharedconfig.WarmUpTimeout
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	start := time.Now()
	if err := tr.WarmUp(ctx); err != nil {
		log.Warn("[WARMUP] failed",
			"err", err,
			"elapsed_ms", time.Since(start).Milliseconds(),
		)
		return err
	}
	log.Info("[WARMUP] done", "elapsed_ms", time.Since(start).Milliseconds())
	return nil
}
