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
	"github.com/nange/easyss/v3/stats"
	"github.com/nange/easyss/v3/transport"
)

// HTTP2Transport is a facade over the HTTP/2 client machinery: streams are
// mapped onto connections by slotScheduler, and the per-connection state
// (degradation, rotation) is driven by slotLifecycle. This type only wires
// the two together and speaks HTTP.
type HTTP2Transport struct {
	sched     *slotScheduler
	lifecycle *slotLifecycle

	serverURL string

	ctx    context.Context
	cancel context.CancelFunc
}

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
	threshold := int32(cfg.StreamThreshold)
	if threshold < 1 {
		threshold = 8
	}

	ratio := cfg.PrioritySlotRatio
	if ratio <= 0 || ratio > 1 {
		ratio = sharedconfig.DefaultPrioritySlotRatio
	}
	prioritySlots := int(float64(maxSlots) * ratio)
	if prioritySlots < 1 {
		prioritySlots = 1
	}
	if prioritySlots > maxSlots {
		prioritySlots = maxSlots
	}

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
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

	t.sched.grow(req.HighPriority)

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

func (t *HTTP2Transport) CloseIdle() {
	// Close idle TCP connections on all slots of both pools (no lock
	// needed).
	for _, pool := range []*slotPool{t.sched.priority, t.sched.bulk} {
		for _, s := range pool.slots {
			s.t.CloseIdleConnections()
		}
	}

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
		for i := 0; i < live; i++ {
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
	return ts
}

// slotStatus derives a live slot's connection status from its health flags.
// Multiple flags are joined with "+" so no state is hidden (a heavy download
// crossing the connection lifetime is both heavy and expiring); a slot with
// no flags is "active".
func slotStatus(s *transportSlot) string {
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
		return "active"
	}
	return strings.Join(parts, "+")
}

// slotStatusString renders the live slots of one pool as
// "<index>:<active streams>:<status>", wrapped in brackets, e.g.
// "[0:3:degraded, 1:2:expiring, 2:1:active, 3:1:heavy]". Entries are
// ordered by the stable slot identity (retire swap-removes scramble the
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
		entries = append(entries, entry{
			idx:    s.idx,
			active: int(s.active.Load()),
			status: slotStatus(s),
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
	for _, pool := range []*slotPool{t.sched.priority, t.sched.bulk} {
		live := int(pool.liveCount.Load())
		for _, s := range pool.slots[:live] {
			s.t.CloseIdleConnections()
		}
	}
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
