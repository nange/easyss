package transport

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"
)

// HandshakeRejectedError 报告服务器以非 200 状态（例如 408 Request Timeout、
// 400 Bad Request）应答 bootstrap 握手，意味着流在交换任何会话记录之前
// 就被拒绝。客户端在首次读取时快速失败，而不是把拒绝正文误解析为加密记录。
type HandshakeRejectedError struct {
	StatusCode int
	Status     string
}

func (e *HandshakeRejectedError) Error() string {
	if e.Status != "" {
		return fmt.Sprintf("handshake rejected: server returned HTTP %d %s", e.StatusCode, e.Status)
	}
	return fmt.Sprintf("handshake rejected: server returned HTTP %d", e.StatusCode)
}

// IsHandshakeRejected 报告 err 是否表示服务器以非 200 状态拒绝了握手。
func IsHandshakeRejected(err error) bool {
	var e *HandshakeRejectedError
	return errors.As(err, &e)
}

type Stream interface {
	io.Reader
	io.Writer
	CloseWrite() error
	Close() error
}

// SlotDrainingStream 由底层连接槽位即将被驱逐的流实现：expiring
// （连接超过其寿命或字节限制）或 degraded（确认持续低速）。代理层断言
// 这个可选接口以提前排空空闲流（见 relay.BidirectionalWithDrain），
// 使残留的 keep-alive 与半关闭连接无法把槽位的轮换/退役推迟到完整的中继
// 空闲超时。未实现该接口的流永远不会排空。
type SlotDrainingStream interface {
	SlotDraining() bool
}

// BootstrapSentMarker 由传输层采样纯客户端<->服务器路径 RTT 的流实现：
// 代理标记 bootstrap 记录刷出的时刻，使传输层能在响应头到达时记录往返
// （服务器在拨号源站之前就提交响应，因此源站延迟永远不会进入样本）。
// 未实现该接口的流不做 RTT 采样。
type BootstrapSentMarker interface {
	MarkBootstrapSent()
}

// ResponseAwaiter 由能在不消费响应体的情况下等待"响应已就绪"的传输层流实现：
// 代理层据此在引导阶段用一个有界窗口等待服务端响应，而不是写完引导记录就
// 假定连接可用。契约必须精确，否则会把"服务端拒绝"误当成网络故障：
//
//   - 响应已就绪（含服务端以非 200 拒绝握手，传输层已把它转成
//     HandshakeRejectedError）→ nil；
//   - 传输层错误 → 该错误；
//   - ctx 结束 → ctx.Err()。
//
// 未实现该接口的流保持原有行为：代理层不等待。
type ResponseAwaiter interface {
	AwaitResponse(ctx context.Context) error
}

// ConnLiveness 由能在本流所在连接上做一次轻量存活探测的传输层流实现：
// 响应头迟到既可能是"连接已死"（网络切换/漫游），也可能是"服务端仍在解析
// 目标域名"，判活探测用来区分二者。ok=false 表示无法判定（服务端不提供
// /v3/probe，或客户端未配置探测令牌），此时调用方应按判死处理。
type ConnLiveness interface {
	ConnAlive(ctx context.Context) (alive, ok bool)
}

// ConnInvalidator 由能强制关闭本流所在底层连接的传输层流实现。
// http.Transport 只暴露 CloseIdleConnections，它关不掉正在承载活跃流的连接，
// 因此"判死即换连接重试"需要传输层按连接身份精确关闭。未实现该接口的流
// 永远不会被调用。
type ConnInvalidator interface {
	InvalidateConn()
}

type OpenRequest struct {
	Endpoint     string
	Salt         string
	HighPriority bool
	// Target 是流的目标地址 "host:port"（域名或 IP）。它从不参与调度——
	// 带上它只是为了把槽位增长事件归因于触发它的请求
	// （见 TransportStats.GrowEvents）。
	Target string
}

type TransportStats struct {
	Conns                 int `json:"conns"`
	ActiveStreams         int `json:"active_streams"`
	PriorityActiveStreams int `json:"priority_active_streams"`
	BulkActiveStreams     int `json:"bulk_active_streams"`
	PriorityConns         int `json:"priority_conns"`
	BulkConns             int `json:"bulk_conns"`
	// PriorityConnsStatus 是 priority 池的紧凑逐连接状态摘要，
	// 例如 "[0:3:degraded, 1:2:expiring, 2:1:active]"。每个元素形如
	// "<index>:<active streams>:<status>"：索引从 0 连续递增（按稳定的
	// 连接身份排序），状态为 idle/active/heavy/degraded/expiring 之一，
	// 多个标记用 "+" 连接。"idle" 表示不承载任何流的健康连接（热连接），
	// 使过去突发增长出来的池与活跃流量可区分。bulk 池以相同方式
	// 渲染进 BulkConnsStatus。
	PriorityConnsStatus string `json:"priority_conns_status,omitempty"`
	BulkConnsStatus     string `json:"bulk_conns_status,omitempty"`
	// GrowEvents 列出最近的槽位增长事件（懒加载扩容调度器激活的新连接），
	// 最新在前，在传输实现中限制为一个小型环形缓冲。每个事件记录增长的池、
	// 增长后的存活槽位数，以及触发增长的请求的 endpoint/target，
	// 让连接数的突然跳升可以归因到造成它的流量。
	GrowEvents []GrowEvent `json:"recent_grow_events,omitempty"`
}

// GrowEvent 是一次槽位增长（新的存活连接）：哪个池增长、
// 增长后的存活槽位数，以及触发它的请求（其协议端点与目标 host:port）。
type GrowEvent struct {
	Time     time.Time `json:"time"`
	Pool     string    `json:"pool"` // "priority" 或 "bulk"
	Live     int       `json:"live"` // 增长后的存活槽位数
	Endpoint string    `json:"endpoint"`
	Target   string    `json:"target"`
}

type Transport interface {
	Open(ctx context.Context, req OpenRequest) (Stream, error)
	// WarmUp 预热每个调度池的首条连接，使每个流量类的首条真实流
	// 复用已建立的连接，而不是付出冷启动代价（拨号 + TLS + HTTP/2）。
	// 实现激活池并在该池的一条连接上发起一次请求；任何应答都证明
	// 路径可用，因此只有无法确认连接的请求才被报告为错误。
	// 按契约尽力而为：实现不得静默丢弃已确定的失败，但如何处理由调用方
	// 决定——启动绝不能依赖预热，通常的处理是记录日志后继续。
	WarmUp(ctx context.Context) error
	CloseIdle()
	Stats() TransportStats
	Close() error
}
