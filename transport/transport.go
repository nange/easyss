package transport

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"
)

// HandshakeRejectedError 表示服务器以非 200 状态应答 bootstrap 握手，流在交换任何会话记录
// 之前就被拒绝。客户端据此快速失败，而不是把拒绝正文误解析为密文。
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

// IsHandshakeRejected 报告 err 是否为握手被拒。
func IsHandshakeRejected(err error) bool {
	var e *HandshakeRejectedError
	return errors.As(err, &e)
}

// ErrConnRetired 表示流所属的连接代已作废。代理层据此把"连接被换掉"与真正的目标错误区分开，
// 不必匹配 stdlib 的错误文本。
var ErrConnRetired = errors.New("transport: connection retired")

type Stream interface {
	io.Reader
	io.Writer
	CloseWrite() error
	Close() error
}

// SlotDrainingStream 由槽位即将被驱逐的流实现，代理层断言它以提前排空空闲流，使残留的
// keep-alive 与半关闭连接无法把轮换推迟到完整的中继空闲超时。
type SlotDrainingStream interface {
	SlotDraining() bool
}

// BootstrapSentMarker 由能采样纯 client<->server 路径 RTT 的流实现：代理标记 bootstrap 记录
// 刷出的时刻，传输层在响应头到达时记录往返（服务器在拨号源站之前就提交响应，源站延迟不进入样本）。
type BootstrapSentMarker interface {
	MarkBootstrapSent()
}

// ResponseAwaiter 由能在不消费响应体的情况下等待响应就绪的流实现。响应已就绪（含以非 200
// 拒绝握手，已转成 HandshakeRejectedError）返回 nil，传输层错误返回该错误，ctx 结束返回 ctx.Err()。
type ResponseAwaiter interface {
	AwaitResponse(ctx context.Context) error
}

// ConnLiveness 由能在本流所在连接上做存活探测的流实现：响应头迟到既可能是连接已死，也可能是
// 服务端仍在解析目标域名。ok=false 表示无法判定，调用方按原样返回超时错误。
type ConnLiveness interface {
	ConnAlive(ctx context.Context) (alive, ok bool)
}

// ConnInvalidator 由能强制关闭本流底层连接的流实现。http.Transport 只暴露
// CloseIdleConnections，关不掉承载活跃流的连接，判死重试因此需要按连接身份精确关闭。
type ConnInvalidator interface {
	InvalidateConn()
}

type OpenRequest struct {
	Endpoint     string
	Salt         string
	HighPriority bool
	// Target 是目标地址 "host:port"，从不参与调度，只用于把槽位增长事件归因到触发它的请求。
	Target string
}

type TransportStats struct {
	Conns                 int `json:"conns"`
	ActiveStreams         int `json:"active_streams"`
	PriorityActiveStreams int `json:"priority_active_streams"`
	BulkActiveStreams     int `json:"bulk_active_streams"`
	PriorityConns         int `json:"priority_conns"`
	BulkConns             int `json:"bulk_conns"`
	// PriorityConnsStatus 是 priority 池逐连接状态摘要，元素形如 "<index>:<active>:<status>"。
	PriorityConnsStatus string `json:"priority_conns_status,omitempty"`
	BulkConnsStatus     string `json:"bulk_conns_status,omitempty"`
	// GrowEvents 是最近的槽位增长事件，最新在前，使连接数的突然跳升可以归因到触发它的流量。
	GrowEvents []GrowEvent `json:"recent_grow_events,omitempty"`
}

// GrowEvent 是一次槽位增长：哪个池、增长后的存活槽位数与触发它的请求。
type GrowEvent struct {
	Time     time.Time `json:"time"`
	Pool     string    `json:"pool"` // "priority" 或 "bulk"
	Live     int       `json:"live"` // 增长后的存活槽位数
	Endpoint string    `json:"endpoint"`
	Target   string    `json:"target"`
}

type Transport interface {
	Open(ctx context.Context, req OpenRequest) (Stream, error)
	CloseIdle()
	Stats() TransportStats
	Close() error
}
