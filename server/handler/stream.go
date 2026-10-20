package handler

import (
	"errors"
	"io"
	"net"

	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/stats"
)

// 结果日志收敛到 serveSession 里唯一的 logHandlerResult，一条流恰好一条；
// Bytes 是服务端到客户端方向的中继字节数（UDP/ICMP 为已推送的载荷总量）。
type streamResult struct {
	Remote string
	Bytes  int64
	// TimedOut 标记结果来自空闲/读取超时，而不是错误。
	TimedOut bool
	Err      error
}

// 只有真实故障才返回 true：帧协议里 FIN（该方向不再写数据）与 RST（流失败）是两个
// 信号，客户端分别处理成正常结束与 ErrStreamReset，io.EOF 绝不能映射成 RST。
func (r streamResult) needsRST() bool {
	return r.Err != nil && !errors.Is(r.Err, io.EOF)
}

// 唯一的结果日志出口：对端离开（正常拆除、取消、空闲超时、目标 EOF）是预期路径，记
// Debug 并计入 server_stream_cancels；真正的故障保持 Info，不会被静默。
func logHandlerResult(res streamResult, target, endpoint, remote string) {
	attrs := []any{"target", target, "endpoint", endpoint, "client", remote}
	if res.Remote != "" {
		attrs = append(attrs, "upstream", res.Remote)
	}
	if res.Bytes > 0 {
		attrs = append(attrs, "bytes", res.Bytes)
	}
	if res.TimedOut {
		attrs = append(attrs, "timed_out", true)
	}

	if !res.needsRST() {
		if res.Err != nil {
			attrs = append(attrs, "err", res.Err)
		}
		log.Debug("[SERVER] handler finished", attrs...)
		return
	}
	if isTransientStreamError(res.Err) {
		stats.RecordServerStreamCancel()
		log.Debug("[SERVER] handler finished", append(attrs, "transient", true, "err", res.Err)...)
		return
	}
	log.Info("[SERVER] handler finished with error", append(attrs, "err", res.Err)...)
}

// remoteString 对 nil 安全：连接可能报告 nil 的 RemoteAddr，直接调用会 panic。
// next-proxy 路径不用它——SOCKS5 连接报告的是代理地址，dialTarget 改记配置的代理。
func remoteString(conn net.Conn) string {
	if conn == nil {
		return ""
	}
	if ra := conn.RemoteAddr(); ra != nil {
		return ra.String()
	}
	return ""
}
