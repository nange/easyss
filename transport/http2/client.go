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

	"github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/stats"
	"github.com/nange/easyss/v3/transport"
)

const maxGrowEvents = 16

type http2Transport struct {
	sched     *slotScheduler
	lifecycle *slotLifecycle

	serverURL string

	// liveness 在指定那一代连接上做存活探测（HEAD /v3/probe），供代理层区分连接已死与
	// 服务端仍在解析目标域名。必须探测流自己那一代；未配置探测令牌时为 nil。
	liveness func(ctx context.Context, gen *slotTransport) (alive, ok bool)

	slowRTT *slowRTTLogLimiter

	// 增长事件的有界环形缓冲，最旧在前，由 growMu 保护。
	growEvents []transport.GrowEvent
	growMu     sync.Mutex

	ctx    context.Context
	cancel context.CancelFunc
}

type Config struct {
	ServerURL         string
	TLSConfig         *utls.Config
	MaxSlotCount      int
	StreamThreshold   int
	PrioritySlotRatio float64
	// Timeouts 由调用方派生：Base 派生空闲与 h2 ping，Dial 是单次 TCP 拨号上限，
	// ConnLifetime 是轮换前的最大存活时长。零值只由 config.Timeouts.Normalize 填充。
	Timeouts     config.Timeouts
	ConnMaxBytes int64 // 轮换前连接在任一方向承载的最大字节数（0 表示默认值）
	DialContext  func(ctx context.Context, network, addr string) (net.Conn, error)
	// ProbeToken 是 /v3/probe 的能力令牌（由主密钥派生）；为空则禁用主动探测。
	ProbeToken string
}

// New 构建传输层。nil 的 TLSConfig 会让 newSlot 克隆时 panic，直接拒绝。
func New(cfg Config) (transport.Transport, error) {
	if cfg.TLSConfig == nil {
		return nil, errors.New("http2: TLSConfig is required")
	}

	maxSlots := cfg.MaxSlotCount
	if maxSlots < 1 {
		maxSlots = 6
	}
	if maxSlots > config.MaxConnCountMax {
		maxSlots = config.MaxConnCountMax
	}
	threshold := int32(cfg.StreamThreshold)
	if threshold < 1 {
		threshold = 8
	}
	if threshold > config.MaxStreamThreshold {
		threshold = config.MaxStreamThreshold
	}

	ratio := cfg.PrioritySlotRatio
	if ratio <= 0 || ratio > 1 {
		ratio = config.DefaultPrioritySlotRatio
	}
	prioritySlots := min(max(int(float64(maxSlots)*ratio), 1), maxSlots)

	timeouts := cfg.Timeouts.Normalize()
	timeout := timeouts.Base

	dialCtx := cfg.DialContext
	if dialCtx == nil {
		dialCtx = defaultDialContext
	}

	connLifetime := timeouts.ConnLifetime
	connMaxBytes := cfg.ConnMaxBytes
	if connMaxBytes <= 0 {
		connMaxBytes = config.DefaultConnMaxBytes
	}

	ctx, cancel := context.WithCancel(context.Background())

	slots := make([]*transportSlot, maxSlots)
	for i := range slots {
		slots[i] = newSlot(cfg.TLSConfig, timeout, dialCtx, connLifetime, timeouts.Dial)
	}

	sched := newScheduler(maxSlots, slots, threshold, prioritySlots)

	slowRTT := newSlowRTTLogLimiter()

	lc := &slotLifecycle{
		sched:        sched,
		connLifetime: connLifetime,
		connMaxBytes: connMaxBytes,
		slowRTT:      slowRTT,
	}
	var liveness func(ctx context.Context, gen *slotTransport) (alive, ok bool)
	if cfg.ProbeToken != "" {
		prober := &slotProber{
			serverURL:   cfg.ServerURL,
			token:       cfg.ProbeToken,
			payloadSize: int64(config.ProbePayloadSize),
			slowRTT:     slowRTT,
		}
		lc.probeFunc = prober.probe
		// 同一端点也用于判活：HEAD 只花一个 RTT。
		liveness = prober.alive
	}

	tr := &http2Transport{
		sched:     sched,
		lifecycle: lc,
		serverURL: cfg.ServerURL,
		liveness:  liveness,
		slowRTT:   slowRTT,
		ctx:       ctx,
		cancel:    cancel,
	}
	go tr.lifecycle.run(ctx)
	return tr, nil
}

func newSlot(utlsCfg *utls.Config, timeout time.Duration, dialContext func(context.Context, string, string) (net.Conn, error), connLifetime, dialBudget time.Duration) *transportSlot {
	if dialContext == nil {
		dialContext = defaultDialContext
	}

	slot := &transportSlot{}
	// 工厂使判死与回收能换上配置相同的空池。
	slot.newGen = func() *slotTransport {
		gen := &slotTransport{slot: slot}
		gen.tr = buildTransport(slot, gen, utlsCfg, timeout, dialContext, connLifetime, dialBudget)
		return gen
	}
	slot.gen.Store(slot.newGen())
	return slot
}

// buildTransport 构建一代连接池（MaxConnsPerHost=1）及其拨号路径，并把连接写进
// gen.conn 使身份与池同源。判死会重建一代，因此这里必须是纯配置。
func buildTransport(slot *transportSlot, gen *slotTransport, utlsCfg *utls.Config, timeout time.Duration, dialContext func(context.Context, string, string) (net.Conn, error), connLifetime, dialBudget time.Duration) *http.Transport {
	protos := &http.Protocols{}
	protos.SetHTTP2(true)
	protos.SetUnencryptedHTTP2(true)

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			NextProtos: config.NextProtos,
		},
		Protocols: protos,
		HTTP2: &http.HTTP2Config{
			MaxReadFrameSize:              config.HTTP2ClientMaxReadFrameSize,
			MaxReceiveBufferPerConnection: config.HTTP2ClientReceiveBufferPerConnection,
			MaxReceiveBufferPerStream:     config.HTTP2ClientReceiveBufferPerStream,
			MaxDecoderHeaderTableSize:     config.HTTP2ClientMaxDecoderHeaderTableSize,
			SendPingTimeout:               2 * timeout,
			PingTimeout:                   timeout / 3,
		},
		ForceAttemptHTTP2:      true,
		MaxConnsPerHost:        1,
		IdleConnTimeout:        6 * timeout,
		MaxResponseHeaderBytes: config.HTTP2ClientMaxResponseHeaderBytes,
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// 拨号预算只包住 TCP 建连，TLS 握手由 ctx 约束。
			dialCtx, cancel := context.WithTimeout(ctx, dialBudget)
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
			// 只有仍是当前一代时才重置轮换状态：新一代的轮换状态不能被迟到的拨号抹掉。
			if slot.generation() == gen {
				slot.resetConn(connLifetime)
			} else {
				// 落在已回收的一代上，不参与健康循环与轮换，直到自身空闲超时。
				log.Debug("[TRANSPORT] dial landed on a retired generation",
					"slot", slot.idx)
			}

			// 用 Swap 而非 Store：归还非 nil 说明这一代已登记过连接——连接满流时
			// net/http 会丢掉 persistConn 再拨一条，MaxConnsPerHost=1 挡不住。
			sc := &slotConn{c: uconn}
			if gen.conn.Swap(sc) != nil {
				stats.RecordSecondConnInGeneration()
				log.Warn("[TRANSPORT] second connection dialed in one generation",
					"slot", slot.idx,
					"active_streams", slot.active.Load())
			}
			return &trackedConn{Conn: uconn, gen: gen, self: sc}, nil
		},
	}
	return tr
}

// trackedConn 是 DialTLSContext 返回给 net/http 的连接，转发关闭是它的契约。关闭即整代
// 作废；清身份与换代走 CAS，因为 net/http 关闭的可能是一条早已被轮换掉的连接。
type trackedConn struct {
	net.Conn
	gen  *slotTransport
	self *slotConn
}

func (c *trackedConn) Close() error {
	// 先换届再关：uTLS 的 Close 会先发 close_notify，对端不响应时最坏要等到写截止时间
	// （5s）。这期间旧身份若还在，迟到的拨号会在同一代里再拨一条（second_conn_in_generation）。
	c.gen.slot.retireGeneration(c.gen, c.self)
	return c.Conn.Close()
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

	// 待机回来的第一个请求常在醒来后立刻到达，早于第一个健康周期，因此发现挂起不能
	// 只靠定时器。采样器与健康循环共享，谁先看到都只算一次。
	t.lifecycle.observeSuspend(time.Now())

	stats.RecordStreamOpened()

	if pool, live := t.sched.grow(req.HighPriority); pool != nil {
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

	// 复核放在槽位计数 +1 之后：复核期间该槽位算"在用"，不会被回收或退役摘掉。
	if slot.reverify.Load() {
		t.reverifySlot(ctx, slot)
	}

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
		slowRTT:   t.slowRTT,
		startTime: time.Now(),
		// 请求身份只用于日志归因，不参与调度或协议决策。
		endpoint: req.Endpoint,
		target:   req.Target,
	}

	go func() {
		// 池在提交这一刻取用，本流的连接身份就锚定在这一代上。
		gen := slot.generation()
		stream.gen.Store(gen)
		resp, err := gen.tr.RoundTrip(httpReq)
		if err != nil {
			_ = pw.CloseWithError(err)
		}
		// 拒绝的响应体是 fallback/错误页面而非加密记录，必须立即失败，否则记录
		// 读取器会把页面误解析为加密数据。
		if err == nil && resp.StatusCode != http.StatusOK {
			rejectErr := &transport.HandshakeRejectedError{StatusCode: resp.StatusCode, Status: resp.Status}
			_ = resp.Body.Close()
			resp = nil
			err = rejectErr
			_ = pw.CloseWithError(err)
		}
		stream.deliver(roundTripResult{resp: resp, err: err})
	}()

	return stream, nil
}

// reverifySlot 用一次 HEAD /v3/probe 复核带挂起嫌疑的槽位：时钟离差只产生嫌疑，判死
// 必须由真实往返给出，假阳性只花一个 RTT。探测跑在 context.WithoutCancel 上。
func (t *http2Transport) reverifySlot(ctx context.Context, slot *transportSlot) {
	slot.reverifyMu.Lock()
	defer slot.reverifyMu.Unlock()
	if !slot.reverify.Load() {
		return
	}

	gen := slot.generation()
	if gen == nil || t.liveness == nil {
		// 无对象可复核或没有判活手段：清掉标记，避免后续开流反复进入这里。
		slot.reverify.Store(false)
		return
	}
	if gen.conn.Load() == nil {
		slot.reverify.Store(false)
		return
	}
	if ctx.Err() != nil {
		// 调用方已取消不代表连接已死，保留嫌疑交给下一次开流。
		return
	}

	verifyCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), config.SuspendReverifyTimeout)
	defer cancel()
	defer slot.reverify.Store(false)

	alive, known := t.liveness(verifyCtx, gen)
	if !known {
		return
	}
	if alive {
		stats.RecordSuspendReverifyAlive()
		log.Debug("[TRANSPORT] suspend reverify: connection still usable",
			"slot", slot.idx,
			"active_streams", slot.active.Load())
		return
	}
	if slot.invalidateConn(gen, "suspend reverify failed") {
		stats.RecordSuspendReverifyReplaced()
	}
}

func protoOfEndpoint(endpoint string) string {
	switch endpoint {
	case config.EndpointTCP:
		return "tcp"
	case config.EndpointUDP:
		return "udp"
	case config.EndpointICMP:
		return "icmp"
	case config.EndpointProbe:
		return "probe"
	}
	return endpoint
}

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
	// 槽位数组由 shrink/retire 在写锁下交换修改，必须持读锁遍历。
	t.sched.mu.RLock()
	for _, pool := range []*slotPool{t.sched.priority, t.sched.bulk} {
		for _, s := range pool.slots {
			s.transport().CloseIdleConnections()
		}
	}
	t.sched.mu.RUnlock()

	t.sched.mu.Lock()
	defer t.sched.mu.Unlock()
	t.sched.shrinkIdleLocked()
}

func (t *http2Transport) Stats() transport.TransportStats {
	// 读锁保证快照一致：不加锁会渲染出多于 Conns 的条目。
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

	t.growMu.Lock()
	for _, v := range slices.Backward(t.growEvents) {
		ts.GrowEvents = append(ts.GrowEvents, v)
	}
	t.growMu.Unlock()
	return ts
}

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

// slotStatusString 渲染 "[0:3:degraded, 1:2:expiring]"；live 必须是调度器锁下快照的
// liveCount，条目数才与 Conns 一致。
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
	// retire 的交换删除会打乱活跃顺序，按稳定索引排序后重新编号。
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
	// shrink/retire 在写锁下交换删除槽位，遍历活跃区间必须持读锁。
	t.sched.mu.RLock()
	for _, pool := range []*slotPool{t.sched.priority, t.sched.bulk} {
		live := int(pool.liveCount.Load())
		for _, s := range pool.slots[:live] {
			s.transport().CloseIdleConnections()
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
