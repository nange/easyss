package handler

import (
	"errors"
	"io"
	"net"

	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/stats"
)

// streamResult 是一条流的结构化结果。三个会话 handler 都返回它（Err 为 nil
// 表示正常结束，包括客户端 FIN、目标 EOF、UDP 空闲超时），而不是让各自在内部
// 记录"流已结束"：日志出口因此收敛到 serveSession 里唯一的一次
// logHandlerResult，一条流恰好产生一条结果日志（此前 TCP 会由 handler 和
// serveSession 各记一条，而 UDP/ICMP 完全没有结果日志，字节数与退出原因不可见）。
//
// Bytes 是服务端到客户端方向的中继字节数（UDP/ICMP 为已推送的载荷总量）。
type streamResult struct {
	// Remote 是出站目标的远端地址，供日志定位实际连上的地址。
	Remote string
	Bytes  int64
	// TimedOut 标记结果来自空闲/读取超时，而不是错误。
	TimedOut bool
	// Err 是退出原因；nil 表示正常结束。
	Err error
}

// needsRST 报告该结果是否应向客户端发送 RST：只有真实故障需要。
//
// RST 与 FIN 在 easyss 帧协议里是两个信号，客户端也区别对待（FIN 结束本地
// 连接，RST 变成 ErrStreamReset 错误）：FIN 表示"这个方向不再写数据"，由
// copyFromTarget/Handle 在正常收尾时主动推送；RST 表示"这条流失败了"。
// 因此 io.EOF 绝不能映射成 RST：它是读取侧对"不再有数据"的惯用表达。
//
// 说明：当前 relay.bidirectional 会把两个拷贝方向返回的 io.EOF 全部过滤掉
// （firstErr 只在非 EOF 时被赋值），UDP 的 io.EOF 也只来自已收尾会话，因此
// 这个判断目前是防御性的。它保留在接口层，是为了让"某个新 handler 直接返回
// io.EOF"时语义仍然正确，而不用依赖 relay 那条不显眼的过滤规则。
func (r streamResult) needsRST() bool {
	return r.Err != nil && !errors.Is(r.Err, io.EOF)
}

// logHandlerResult 是唯一的结果日志出口。对端已离开该流（客户端正常拆除、
// HTTP/2 流被取消、中继空闲超时、目标正常 EOF）属于预期路径：客户端每关闭一个
// 连接都会产生一条这样的结果，因此降到 Debug，并把它们计入
// server_stream_cancels 计数器，使"被静音的拆除"仍然可观测。真正的故障
// （拨号失败、目标重置、解密失败）保持 Info + err=，不会被淹没。
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

	// Err 为 nil（正常结束）与 io.EOF（读取侧的正常终止表达）都属于预期路径。
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

// remoteString 返回用于日志的可打印远端端点。它特意对 nil 安全：拨号得到的
// 连接可能报告未设置（nil）的 RemoteAddr，直接调用 RemoteAddr().String()
// 会 panic。next-proxy 路径不使用它（SOCKS5 连接报告的是代理的地址，
// 因此 dialTarget 改为记录配置的代理）。
func remoteString(conn net.Conn) string {
	if conn == nil {
		return ""
	}
	if ra := conn.RemoteAddr(); ra != nil {
		return ra.String()
	}
	return ""
}
