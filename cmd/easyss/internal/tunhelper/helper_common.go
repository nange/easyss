package tunhelper

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/nange/easyss/v3/client/proxy"
)

// 单次请求 5 秒超时；退避重试给主进程的 HTTP 服务留出启动窗口。
func fetchTunConfig(httpAddr string) (*proxy.TunConfig, error) {
	url := fmt.Sprintf("http://%s/tun", httpAddr)
	client := &http.Client{Timeout: 5 * time.Second}

	var lastErr error
	for i := range 10 {
		if i > 0 {
			time.Sleep(time.Duration(i) * 200 * time.Millisecond)
		}

		resp, err := client.Get(url) //nolint:gosec
		if err != nil {
			lastErr = err
			continue
		}
		// 每次迭代都关闭 body：改用 defer 的话，之前十次响应的 body 会一直开到函数返回。
		if resp.StatusCode == http.StatusServiceUnavailable {
			_ = resp.Body.Close()
			lastErr = fmt.Errorf("tun not configured yet (503)")
			continue
		}
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
			_ = resp.Body.Close()
			lastErr = fmt.Errorf("GET /tun returned %d: %s", resp.StatusCode, string(body))
			continue
		}

		var cfg proxy.TunConfig
		decodeErr := json.NewDecoder(resp.Body).Decode(&cfg)
		_ = resp.Body.Close()
		if decodeErr != nil {
			lastErr = fmt.Errorf("decode tun config: %w", decodeErr)
			continue
		}

		return &cfg, nil
	}

	// 错误只说明重试本身，失败步骤由调用方命名。
	return nil, fmt.Errorf("after retries: %w", lastErr)
}

// 它会出现在桌面通知里，而平台脚本失败时可能产生大段引用的命令输出。
const maxHelperFailureReason = 512

// 桌面通知渲染不了换行，控制通道也只承载一条消息。超限文本保留两端：开头是失败的步骤，
// 结尾是脚本的 "failed near:" 摘要。
func failurePayload(reason error) []byte {
	if reason == nil {
		return nil
	}
	msg := strings.Join(strings.Fields(reason.Error()), " ")
	if len(msg) > maxHelperFailureReason {
		const ellipsis = " ... "
		keep := maxHelperFailureReason - len(ellipsis)
		msg = msg[:keep/2] + ellipsis + msg[len(msg)-(keep-keep/2):]
	}
	return []byte(msg)
}
