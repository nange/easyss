package http2

import (
	"context"
	"crypto/tls"
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

// maxGrowEvents bounds the ring of recent slot-growth events exposed via
// TransportStats.GrowEvents — enough to attribute a connection-count jump
// to its triggering requests without unbounded memory growth.
const maxGrowEvents = 16

// HTTP2Transport is a facade over the HTTP/2 client machinery: streams are
// mapped onto connections by slotScheduler, and the per-connection state
// (degradation, rotation) is driven by slotLifecycle. This type only wires
// the two together and speaks HTTP.
type HTTP2Transport struct {
	sched     *slotScheduler
	lifecycle *slotLifecycle

	serverURL string

	// growEvents is a bounded ring of recent slot-growth events, oldest
	// first; snapshotted (newest first) into TransportStats.GrowEvents.
	// Guarded by growMu.
	growEvents []transport.GrowEvent
	growMu     sync.Mutex

	ctx    context.Context
	cancel context.CancelFunc
}

// The slot-count and stream-threshold bounds live in the shared config
// package (MaxConnCountMax, MaxStreamThreshold) so the client config
// clamping and the transport guard always agree; see config/types.go for
// the rationale.

type Config struct {
	ServerURL         string
	TLSConfig         *utls.Config
	MaxSlotCount      int
	StreamThreshold   int
	PrioritySlotRatio float64
	ConnLifetime      time.Duration // max age of a connection before rotation (0: default)
	ConnMaxBytes      int64         // max bytes carried by a connection in either direction before rotation (0: default)
	Timeout           time.Duration
	DialContext       func(ctx context.Context, network, addr string) (net.Conn, error)
	// ProbeToken is the capability token for the server's /v3/probe
	// endpoint (derived from the master key). Empty disables active
	// probing, leaving passive-only degraded detection.
	ProbeToken string
}

func New(cfg Config) (*HTTP2Transport, error) {
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

	// Pre-allocate and initialize all slots. Transports are cheap structs;
	// actual TCP connections are established lazily by Go's http.Transport.
	// Per-pool stable indices are assigned by newScheduler.
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
	if cfg.ProbeToken != "" {
		prober := &slotProber{
			serverURL:   cfg.ServerURL,
			token:       cfg.ProbeToken,
			payloadSize: int64(sharedconfig.ProbePayloadSize),
		}
		lc.probeFunc = prober.probe
	}

	tr := &HTTP2Transport{
		sched:     sched,
		lifecycle: lc,
		serverURL: cfg.ServerURL,
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
			// A new connection resets the rotation state: the lifetime
			// deadline (with per-connection jitter), bytes carried and the
			// expiring mark all start fresh.
			slot.resetConn(connLifetime)
			return uconn, nil
		},
	}
	slot.t = tr
	return slot
}

func defaultDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	dialer := &net.Dialer{
		KeepAlive: 30 * time.Second,
	}
	return dialer.DialContext(ctx, network, addr)
}

func (t *HTTP2Transport) Open(ctx context.Context, req transport.OpenRequest) (transport.Stream, error) {
	if t.ctx.Err() != nil {
		return nil, t.ctx.Err()
	}

	stats.RecordStreamOpened()

	if pool, live := t.sched.grow(req.HighPriority); pool != nil {
		// This request actually triggered a slot expansion: attribute the
		// growth to it. Concurrent growers serialize on the scheduler write
		// lock and re-evaluate under it, so only the request that performed
		// the activation reaches this branch.
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

	respCh := make(chan roundTripResult, 1)

	var stream *HTTP2Stream
	doneOnce := sync.OnceFunc(func() {
		// Release the slot's heavy mark exactly once (doneOnce runs at most
		// a single time), so the slot becomes eligible for new streams again.
		stream.releaseHeavy()
		slot.active.Add(-1)
		stats.RecordStreamClosed()
		cancel()
	})

	stream = &HTTP2Stream{
		w:         pw,
		respCh:    respCh,
		cancel:    cancel,
		done:      doneOnce,
		slot:      slot,
		startTime: time.Now(),
	}

	go func() {
		resp, err := slot.t.RoundTrip(httpReq)
		if err != nil {
			_ = pw.CloseWithError(err)
		}
		// Rejections are answered with plain HTTP error statuses (408/400/
		// 404/405/429...): the body would be a fallback/error page, not
		// encrypted records. Fail the stream immediately with a clear error
		// so the record reader never misparses the rejection body.
		if err == nil && resp.StatusCode != http.StatusOK {
			rejectErr := &transport.HandshakeRejectedError{StatusCode: resp.StatusCode, Status: resp.Status}
			_ = resp.Body.Close()
			resp = nil
			err = rejectErr
			_ = pw.CloseWithError(err)
		}
		// Store the RoundTrip error on the stream so Write() can surface it
		// when the pipe write fails with io.ErrClosedPipe.
		stream.setRoundTripErr(err)
		respCh <- roundTripResult{resp: resp, err: err}
	}()

	return stream, nil
}

// protoOfEndpoint maps a proxy endpoint path to its short protocol name
// for growth-event logging; unknown paths are echoed as-is.
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

// recordGrowEvent appends one slot-growth event to the bounded ring,
// dropping the oldest beyond maxGrowEvents. The ring is snapshotted
// newest-first into TransportStats.GrowEvents by Stats.
func (t *HTTP2Transport) recordGrowEvent(pool string, live int32, req transport.OpenRequest) {
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

func (t *HTTP2Transport) CloseIdle() {
	// Close idle TCP connections on all slots of both pools. The slot array
	// elements are swap-mutated by shrink/retire under the scheduler write
	// lock, so read the arrays under the read lock.
	t.sched.mu.RLock()
	for _, pool := range []*slotPool{t.sched.priority, t.sched.bulk} {
		for _, s := range pool.slots {
			s.t.CloseIdleConnections()
		}
	}
	t.sched.mu.RUnlock()

	// Shrink liveCount by retiring idle slots (any position, swap-remove).
	t.sched.mu.Lock()
	defer t.sched.mu.Unlock()
	t.sched.shrinkIdleLocked()
}

func (t *HTTP2Transport) Stats() transport.TransportStats {
	// Hold the scheduler read lock so the snapshot is consistent: shrink
	// (swap-remove) and grow mutate pool liveCounts and the live slot
	// ranges under the write lock, so an unlocked render could read a
	// stale liveCount and report more conns_status entries than Conns.
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

	// Snapshot the recent growth events newest-first. The ring has its own
	// mutex (recordGrowEvent holds no scheduler lock), so no lock ordering
	// issue with the read lock held above.
	t.growMu.Lock()
	for _, v := range slices.Backward(t.growEvents) {
		ts.GrowEvents = append(ts.GrowEvents, v)
	}
	t.growMu.Unlock()
	return ts
}

// slotStatus derives a live slot's connection status from its health flags
// and the number of streams currently hosted on it. Multiple flags are
// joined with "+" so no state is hidden (a heavy download crossing the
// connection lifetime is both heavy and expiring). A slot with no flags
// hosting at least one stream is "active"; one with no flags and no streams
// is an idle warm connection and renders as "idle", so a pool full of
// connection slots but few streams is not mistaken for active traffic.
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

// slotStatusString renders the live slots of one pool as
// "<index>:<active streams>:<status>", wrapped in brackets, e.g.
// "[0:3:degraded, 1:2:expiring, 2:1:active, 3:1:heavy]". A healthy slot
// hosting no streams renders as "0:idle" (a warm connection), so a burst
// that grew the pool is distinguishable from real active traffic. Entries
// are ordered by the stable slot identity (retire swap-removes scramble the
// live order) and then renumbered from 0, so the rendered indices are
// always consecutive with no jumps. An empty live set renders as "[]".
// live must be the pool's liveCount value the caller snapshot under the
// scheduler lock, so the rendered entry count always matches Conns.
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
	// Order by stable slot index regardless of the scrambled live order,
	// then number entries 0..n-1 so the output indices never jump.
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

func (t *HTTP2Transport) Close() error {
	t.cancel()
	// Read the live slot ranges under the scheduler read lock: shrink/retire
	// swap-remove slots under the write lock, so an unlocked iteration over
	// the live range would race with those swaps.
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

var _ transport.Transport = (*HTTP2Transport)(nil)
