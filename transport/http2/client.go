package http2

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"

	sharedconfig "github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/stats"
	"github.com/nange/easyss/v3/transport"
)

// maxGrowEvents 限制通过 TransportStats.GrowEvents 暴露的近期槽位增长事件环形
// 缓冲大小——足以把连接数跳变归因到触发它的请求，同时避免无界的内存增长。
const maxGrowEvents = 16

// http2Transport 是 HTTP/2 客户端机制的门面：流由 slotScheduler 映射到连接上，
// 每连接的状态（降级、轮换）由 slotLifecycle 驱动。该类型只负责把两者
// 连接起来并对外提供 HTTP 能力。
type http2Transport struct {
	sched     *slotScheduler
	lifecycle *slotLifecycle

	serverURL string

	// liveness 在某个槽位的连接上做一次轻量存活探测（HEAD /v3/probe），供
	// 代理层区分"连接已死"与"服务端还在解析目标域名"。未配置探测令牌时为 nil。
	liveness func(ctx context.Context, slot *transportSlot) (alive, ok bool)

	// growEvents 是近期槽位增长事件的有界环形缓冲，最旧的在最前；
	// 以最新优先的顺序快照进 TransportStats.GrowEvents。由 growMu 保护。
	growEvents []transport.GrowEvent
	growMu     sync.Mutex

	ctx    context.Context
	cancel context.CancelFunc
}

// 槽位数量与流阈值上限定义在共享 config 包中（MaxConnCountMax、
// MaxStreamThreshold），这样客户端配置的钳制与传输层的防护总是保持一致；
// 理由详见 config/types.go。

type Config struct {
	ServerURL         string
	TLSConfig         *utls.Config
	MaxSlotCount      int
	StreamThreshold   int
	PrioritySlotRatio float64
	ConnLifetime      time.Duration // 连接轮换前的最大存活时长（0：使用默认值）
	ConnMaxBytes      int64         // 轮换前连接在任一方向承载的最大字节数（0：使用默认值）
	Timeout           time.Duration
	DialContext       func(ctx context.Context, network, addr string) (net.Conn, error)
	// ProbeToken 是服务端 /v3/probe 端点的能力令牌（由主密钥派生）。
	// 为空则禁用主动探测，只保留被动式降级检测。
	ProbeToken string
}

// New 构建传输层。返回的错误是契约性的：nil 的 TLSConfig 无法完成拨号
// （newSlot 会克隆它），因此在这里直接拒绝，而不是在第一次 Open 时 panic。
func New(cfg Config) (transport.Transport, error) {
	if cfg.TLSConfig == nil {
		return nil, errors.New("http2: TLSConfig is required")
	}

	maxSlots := cfg.MaxSlotCount
	if maxSlots < 1 {
		maxSlots = 6
	}
	if maxSlots > sharedconfig.MaxConnCountMax {
		maxSlots = sharedconfig.MaxConnCountMax
	}
	threshold := int32(cfg.StreamThreshold)
	if threshold < 1 {
		threshold = 8
	}
	if threshold > sharedconfig.MaxStreamThreshold {
		threshold = sharedconfig.MaxStreamThreshold
	}

	ratio := cfg.PrioritySlotRatio
	if ratio <= 0 || ratio > 1 {
		ratio = sharedconfig.DefaultPrioritySlotRatio
	}
	prioritySlots := min(max(int(float64(maxSlots)*ratio), 1), maxSlots)

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = time.Duration(sharedconfig.DefaultTimeout) * time.Second
	}

	dialCtx := cfg.DialContext
	if dialCtx == nil {
		dialCtx = defaultDialContext
	}

	connLifetime := cfg.ConnLifetime
	if connLifetime <= 0 {
		connLifetime = time.Duration(sharedconfig.DefaultConnLifetimeSec) * time.Second
	}
	connMaxBytes := cfg.ConnMaxBytes
	if connMaxBytes <= 0 {
		connMaxBytes = sharedconfig.DefaultConnMaxBytes
	}

	ctx, cancel := context.WithCancel(context.Background())

	// 预分配并初始化所有槽位。Transport 是廉价的 struct；
	// 真正的 TCP 连接由 Go 的 http.Transport 惰性建立。
	// 每个池内的稳定索引由 newScheduler 分配。
	slots := make([]*transportSlot, maxSlots)
	for i := range slots {
		slots[i] = newSlot(cfg.TLSConfig, timeout, dialCtx, connLifetime)
	}

	sched := newScheduler(maxSlots, slots, threshold, prioritySlots)

	lc := &slotLifecycle{
		sched:        sched,
		connLifetime: connLifetime,
		connMaxBytes: connMaxBytes,
	}
	var liveness func(ctx context.Context, slot *transportSlot) (alive, ok bool)
	if cfg.ProbeToken != "" {
		prober := &slotProber{
			serverURL:   cfg.ServerURL,
			token:       cfg.ProbeToken,
			payloadSize: int64(sharedconfig.ProbePayloadSize),
		}
		lc.probeFunc = prober.probe
		// 同一个探测端点也用于"判活"：HEAD 只花一个 RTT，不需下载载荷。
		liveness = prober.alive
	}

	tr := &http2Transport{
		sched:     sched,
		lifecycle: lc,
		serverURL: cfg.ServerURL,
		liveness:  liveness,
		ctx:       ctx,
		cancel:    cancel,
	}
	go tr.lifecycle.run(ctx)
	return tr, nil
}

func newSlot(utlsCfg *utls.Config, timeout time.Duration, dialContext func(context.Context, string, string) (net.Conn, error), connLifetime time.Duration) *transportSlot {
	if dialContext == nil {
		dialContext = defaultDialContext
	}

	slot := &transportSlot{}

	protos := &http.Protocols{}
	protos.SetHTTP2(true)
	protos.SetUnencryptedHTTP2(true)

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			NextProtos: sharedconfig.NextProtos,
		},
		Protocols: protos,
		HTTP2: &http.HTTP2Config{
			MaxReadFrameSize:              sharedconfig.HTTP2ClientMaxReadFrameSize,
			MaxReceiveBufferPerConnection: sharedconfig.HTTP2ClientReceiveBufferPerConnection,
			MaxReceiveBufferPerStream:     sharedconfig.HTTP2ClientReceiveBufferPerStream,
			MaxDecoderHeaderTableSize:     sharedconfig.HTTP2ClientMaxDecoderHeaderTableSize,
			SendPingTimeout:               2 * timeout,
			PingTimeout:                   timeout / 3,
		},
		ForceAttemptHTTP2:      true,
		MaxConnsPerHost:        1,
		IdleConnTimeout:        6 * timeout,
		MaxResponseHeaderBytes: sharedconfig.HTTP2ClientMaxResponseHeaderBytes,
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialCtx, cancel := context.WithTimeout(ctx, timeout/2)
			defer cancel()

			tcpConn, err := dialContext(dialCtx, network, addr)
			if err != nil {
				return nil, err
			}

			ucfg := utlsCfg.Clone()
			if ucfg.ServerName == "" {
				host, _, err := net.SplitHostPort(addr)
				if err == nil {
					ucfg.ServerName = host
				}
			}

			uconn := utls.UClient(tcpConn, ucfg, utls.HelloChrome_Auto)
			if err := uconn.HandshakeContext(ctx); err != nil {
				_ = tcpConn.Close()
				return nil, err
			}
			if proto := uconn.ConnectionState().NegotiatedProtocol; proto != "h2" {
				_ = uconn.Close()
				return nil, fmt.Errorf("server negotiated %q, want h2", proto)
			}
			// 新连接会重置轮换状态：生命周期截止时间（含每连接抖动）、
			// 已承载字节数和 expiring 标记都从零开始。
			slot.resetConn(connLifetime)

			// 记录这条连接的身份，使判死路径能精确关闭承载活跃流的连接
			// （http.Transport 自己关不掉它）。只有这里写入指针；清除一律走
			// CAS（trackedConn.Close、http2Stream.InvalidateConn）。
			sc := &slotConn{c: uconn}
			slot.conn.Store(sc)
			return &trackedConn{Conn: uconn, slot: slot, self: sc}, nil
		},
	}
	slot.t = tr
	return slot
}

// trackedConn 是 DialTLSContext 返回给 net/http 的连接：转发关闭是它的契约
// （net/http 回收连接时调用），但清除槽位指针必须走 CAS——net/http 关闭的
// 可能是一条早已被轮换掉的连接，绝不能把新连接的指针清掉。
type trackedConn struct {
	net.Conn
	slot *transportSlot
	self *slotConn
}

func (c *trackedConn) Close() error {
	err := c.Conn.Close()
	c.slot.conn.CompareAndSwap(c.self, nil)
	return err
}

func defaultDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	dialer := &net.Dialer{
		KeepAlive: 30 * time.Second,
	}
	return dialer.DialContext(ctx, network, addr)
}

func (t *http2Transport) Open(ctx context.Context, req transport.OpenRequest) (transport.Stream, error) {
	if t.ctx.Err() != nil {
		return nil, t.ctx.Err()
	}

	stats.RecordStreamOpened()

	if pool, live := t.sched.grow(req.HighPriority); pool != nil {
		// 该请求确实触发了槽位扩容：把这次增长归因于它。并发的扩容者会在
		// 调度器的写锁上串行化并在锁内重新评估，因此只有真正执行了激活的
		// 请求才会走到这个分支。
		poolName := "bulk"
		if pool == t.sched.priority {
			poolName = "priority"
			stats.RecordSlotGrownPriority()
		} else {
			stats.RecordSlotGrownBulk()
		}
		log.Info("[TRANSPORT] slot grown",
			"pool", poolName,
			"live", live,
			"endpoint", req.Endpoint,
			"proto", protoOfEndpoint(req.Endpoint),
			"target", req.Target,
			"priority", req.HighPriority)
		t.recordGrowEvent(poolName, live, req)
	}

	t.sched.mu.RLock()
	slot := t.sched.pick(req.HighPriority)
	slot.active.Add(1)
	if req.HighPriority {
		stats.RecordStreamOpenedPriority()
	} else {
		stats.RecordStreamOpenedBulk()
	}
	t.sched.mu.RUnlock()

	parentCtx := ctx
	ctx, cancel := context.WithCancel(parentCtx)

	go func() {
		select {
		case <-t.ctx.Done():
			cancel()
		case <-parentCtx.Done():
			cancel()
		case <-ctx.Done():
		}
	}()

	pr, pw := io.Pipe()
	url := t.serverURL + req.Endpoint
	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, pr)
	if err != nil {
		pw.Close() //nolint:errcheck
		cancel()
		slot.active.Add(-1)
		stats.RecordStreamClosed()
		return nil, err
	}
	httpReq.Header.Set("User-Agent", chromeUserAgent())
	httpReq.Header.Set("Content-Type", "application/octet-stream")
	httpReq.Header.Set("Cache-Control", "no-store")
	if req.Salt != "" {
		httpReq.Header.Set("x-es", req.Salt)
	}

	var stream *http2Stream
	doneOnce := sync.OnceFunc(func() {
		// 恰好释放一次槽位的 heavy 标记（doneOnce 最多执行一次），
		// 使槽位重新可以承接新的流。
		stream.releaseHeavy()
		slot.active.Add(-1)
		stats.RecordStreamClosed()
		cancel()
	})

	stream = &http2Stream{
		w:         pw,
		respReady: make(chan struct{}),
		cancel:    cancel,
		done:      doneOnce,
		slot:      slot,
		liveness:  t.liveness,
		startTime: time.Now(),
	}

	go func() {
		resp, err := slot.t.RoundTrip(httpReq)
		if err != nil {
			_ = pw.CloseWithError(err)
		}
		// 拒绝会以普通 HTTP 错误状态码应答（408/400/404/405/429...）：
		// 响应体将是 fallback/错误页面，而不是加密记录。立即以明确的错误
		// 让流失败，这样记录读取器永远不会误解析拒绝响应体。
		if err == nil && resp.StatusCode != http.StatusOK {
			rejectErr := &transport.HandshakeRejectedError{StatusCode: resp.StatusCode, Status: resp.Status}
			_ = resp.Body.Close()
			resp = nil
			err = rejectErr
			_ = pw.CloseWithError(err)
		}
		// 落定结果：同时供 Read 消费、供 AwaitResponse 观察，以及供 Write
		// 在管道写入失败时呈现根本原因。
		stream.deliver(roundTripResult{resp: resp, err: err})
	}()

	return stream, nil
}

// WarmUp 预热两个调度池各自的第一个连接，使每一类的第一条真实流能复用已建立的
// 连接，而不用付出冷启动代价（拨号 + TLS + HTTP/2）：交互式流（443/80/8080/
// 8443/22 端口上的浏览）位于 priority 池，其他一切（53 端口的 DNS、任意端口）
// 位于 bulk 池。每个池都通过其某个槽位上的一次真实探测请求来预热——槽位的
// http.Transport 会把请求固定到该槽位自己的连接上，因此这次同步往返就能
// 建立连接。任何应答都算数：探测载荷、fallback 页面（不支持 /v3/probe 的
// 服务器）或拒绝都能证明路径可用；只有无法确认连接的探测才会被报告，
// 调用方记录日志后吞掉它：启动绝不能依赖预热。
func (t *http2Transport) WarmUp(ctx context.Context) error {
	if t.lifecycle.probeFunc == nil {
		return errors.New("probe not configured")
	}

	var firstErr error
	for _, highPriority := range []bool{true, false} {
		if err := t.warmPool(ctx, highPriority); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// warmPool 激活一个调度池（首次激活会新增 2 个槽位），并通过该池某个槽位上的
// 一次探测请求建立它的第一个连接。与 Open 一样，pick 必须在调度器读锁下执行。
// 无法确认连接的探测会以 errProbeNotConfirmed 报告，并包裹池名，以便调用方
// 知道哪个流量类别仍然处于冷状态。
func (t *http2Transport) warmPool(ctx context.Context, highPriority bool) error {
	t.sched.grow(highPriority)
	t.sched.mu.RLock()
	slot := t.sched.pick(highPriority)
	t.sched.mu.RUnlock()

	poolName := "bulk"
	if highPriority {
		poolName = "priority"
	}

	if _, verdict := t.lifecycle.probeFunc(ctx, slot); verdict == probeInconclusive {
		// 探测未能确认连接：拨号/TLS 失败（池保持冷状态）或服务端返回了
		// 临时性拒绝。无论哪种情况，都是尽力而为：报告并让调用方决定。
		return fmt.Errorf("warm up %s pool: %w", poolName, errProbeNotConfirmed)
	}
	return nil
}

// protoOfEndpoint 把代理端点路径映射为简短协议名，用于增长事件日志；
// 未知路径原样返回。
func protoOfEndpoint(endpoint string) string {
	switch endpoint {
	case sharedconfig.EndpointTCP:
		return "tcp"
	case sharedconfig.EndpointUDP:
		return "udp"
	case sharedconfig.EndpointICMP:
		return "icmp"
	}
	return endpoint
}

// recordGrowEvent 把一个槽位增长事件追加到有界环形缓冲中，
// 超出 maxGrowEvents 时丢弃最旧的。Stats 会以最新优先的顺序把
// 该环形缓冲快照进 TransportStats.GrowEvents。
func (t *http2Transport) recordGrowEvent(pool string, live int32, req transport.OpenRequest) {
	ev := transport.GrowEvent{
		Time:     time.Now(),
		Pool:     pool,
		Live:     int(live),
		Endpoint: req.Endpoint,
		Target:   req.Target,
	}
	t.growMu.Lock()
	defer t.growMu.Unlock()
	t.growEvents = append(t.growEvents, ev)
	if len(t.growEvents) > maxGrowEvents {
		t.growEvents = append([]transport.GrowEvent(nil), t.growEvents[len(t.growEvents)-maxGrowEvents:]...)
	}
}

func (t *http2Transport) CloseIdle() {
	// 关闭两个池所有槽位上的空闲 TCP 连接。槽位数组元素会被 shrink/retire
	// 在调度器写锁下交换修改，因此要在读锁下读取数组。
	t.sched.mu.RLock()
	for _, pool := range []*slotPool{t.sched.priority, t.sched.bulk} {
		for _, s := range pool.slots {
			s.t.CloseIdleConnections()
		}
	}
	t.sched.mu.RUnlock()

	// 通过退役空闲槽位来缩减 liveCount（任意位置，交换删除）。
	t.sched.mu.Lock()
	defer t.sched.mu.Unlock()
	t.sched.shrinkIdleLocked()
}

func (t *http2Transport) Stats() transport.TransportStats {
	// 持有调度器读锁以保证快照一致：shrink（交换删除）和 grow 会在写锁下
	// 修改池的 liveCount 与活跃槽位区间，因此不加锁的渲染可能读到过期的
	// liveCount，报告的 conns_status 条目数会多于 Conns。
	t.sched.mu.RLock()
	defer t.sched.mu.RUnlock()

	pLive := int(t.sched.priority.liveCount.Load())
	bLive := int(t.sched.bulk.liveCount.Load())
	ts := transport.TransportStats{
		Conns:         pLive + bLive,
		PriorityConns: pLive,
		BulkConns:     bLive,
	}

	for _, pool := range []*slotPool{t.sched.priority, t.sched.bulk} {
		live := int(pool.liveCount.Load())
		for i := range live {
			a := int(pool.slots[i].active.Load())
			ts.ActiveStreams += a
			if pool == t.sched.priority {
				ts.PriorityActiveStreams += a
			} else {
				ts.BulkActiveStreams += a
			}
		}
	}
	ts.PriorityConnsStatus = slotStatusString(t.sched.priority, pLive)
	ts.BulkConnsStatus = slotStatusString(t.sched.bulk, bLive)

	// 以最新优先的顺序快照近期的增长事件。环形缓冲有自己的互斥锁
	// （recordGrowEvent 不持有调度器锁），因此与上面持有的读锁不存在
	// 锁顺序问题。
	t.growMu.Lock()
	for _, v := range slices.Backward(t.growEvents) {
		ts.GrowEvents = append(ts.GrowEvents, v)
	}
	t.growMu.Unlock()
	return ts
}

// slotStatus 根据槽位的健康标记以及当前承载的流数量推导其连接状态。
// 多个标记用 "+" 连接，以免隐藏任何状态（跨越连接生命周期的重下载既是
// heavy 又是 expiring）。无标记且承载至少一条流的槽位是 "active"；
// 无标记且无流的槽位是空闲的预热连接，渲染为 "idle"，这样满是连接槽位
// 但流很少的池不会被误认为是活跃流量。
func slotStatus(s *transportSlot, active int) string {
	var parts []string
	if s.heavy.Load() > 0 {
		parts = append(parts, "heavy")
	}
	if s.degraded.Load() {
		parts = append(parts, "degraded")
	}
	if s.expiring.Load() {
		parts = append(parts, "expiring")
	}
	if len(parts) == 0 {
		if active == 0 {
			return "idle"
		}
		return "active"
	}
	return strings.Join(parts, "+")
}

// slotStatusString 把一个池的活跃槽位渲染为 "<index>:<active streams>:<status>"，
// 外面包上括号，例如 "[0:3:degraded, 1:2:expiring, 2:1:active, 3:1:heavy]"。
// 无流承载的健康槽位渲染为 "0:idle"（预热连接），这样因突发流量而扩大的池
// 与真正的活跃流量可以区分。条目按稳定的槽位身份排序（retire 的交换删除会
// 打乱活跃顺序），然后从 0 重新编号，因此渲染出的索引始终连续、无跳号。
// 活跃集合为空时渲染为 "[]"。live 必须是调用方在调度器锁下快照的池
// liveCount 值，这样渲染出的条目数始终与 Conns 一致。
func slotStatusString(pool *slotPool, live int) string {
	if live > pool.maxSlots {
		live = pool.maxSlots
	}
	type entry struct {
		idx    int
		active int
		status string
	}
	entries := make([]entry, 0, live)
	for i := 0; i < live; i++ {
		s := pool.slots[i]
		a := int(s.active.Load())
		entries = append(entries, entry{
			idx:    s.idx,
			active: a,
			status: slotStatus(s, a),
		})
	}
	if len(entries) == 0 {
		return "[]"
	}
	// 无论活跃顺序如何被打乱，都按稳定的槽位索引排序，
	// 然后把条目编号为 0..n-1，使输出索引永不跳号。
	slices.SortFunc(entries, func(a, b entry) int { return a.idx - b.idx })

	var b strings.Builder
	b.WriteByte('[')
	for i, e := range entries {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(strconv.Itoa(i))
		b.WriteByte(':')
		b.WriteString(strconv.Itoa(e.active))
		b.WriteByte(':')
		b.WriteString(e.status)
	}
	b.WriteByte(']')
	return b.String()
}

func (t *http2Transport) Close() error {
	t.cancel()
	// 在调度器读锁下读取活跃槽位区间：shrink/retire 在写锁下交换删除槽位，
	// 因此不加锁地遍历活跃区间会与这些交换产生竞争。
	t.sched.mu.RLock()
	for _, pool := range []*slotPool{t.sched.priority, t.sched.bulk} {
		live := int(pool.liveCount.Load())
		for _, s := range pool.slots[:live] {
			s.t.CloseIdleConnections()
		}
	}
	t.sched.mu.RUnlock()
	return nil
}

func chromeUserAgent() string {
	ver := utls.HelloChrome_Auto.Version
	switch runtime.GOOS {
	case "windows":
		return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" + ver + ".0.0.0 Safari/537.36"
	case "darwin":
		return "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" + ver + ".0.0.0 Safari/537.36"
	case "android":
		return "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" + ver + ".0.0.0 Mobile Safari/537.36"
	default:
		return "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" + ver + ".0.0.0 Safari/537.36"
	}
}

var _ transport.Transport = (*http2Transport)(nil)
