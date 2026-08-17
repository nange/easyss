package http2

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	utls "github.com/refraction-networking/utls"

	sharedconfig "github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/stats"
	"github.com/nange/easyss/v3/transport"
)

type transportSlot struct {
	t      *http.Transport
	active atomic.Int32
	heavy  atomic.Int32 // number of active heavy streams (>= HeavyStreamThreshold bytes)
	// bytesRecv is the cumulative downloaded bytes across streams on this
	// slot; sampled by the health loop to estimate recent throughput.
	bytesRecv atomic.Int64
	// degraded marks a slot whose download throughput stays below the
	// degraded threshold while hosting heavy streams; new streams avoid it
	// and its idle connection is retired early.
	degraded atomic.Bool

	// Connection rotation state.
	connStart     atomic.Int64 // unix nano of the last successful dial on this slot
	connBytesRecv atomic.Int64 // bytes downloaded over the current connection
	// expiring marks a slot whose connection exceeded the lifetime or bytes
	// limit; new streams avoid it and its idle connection is closed so the
	// next stream dials a fresh one. Cleared when a new connection is
	// established or the rotation completes.
	expiring atomic.Bool

	// Health-loop state, touched only from the health loop goroutine.
	lastBytes     int64
	lastHeavy     int // last observed heavy count, tracks heavy 0->1 transitions
	lowCycles     int
	recoverCycles int
}

type HTTP2Transport struct {
	slots         []*transportSlot // pre-allocated and initialized to maxSlots
	liveCount     atomic.Int32     // number of currently active slots (0..maxSlots)
	maxSlots      int
	threshold     int32
	prioritySlots int // number of priority slots (0..prioritySlots-1)
	bulkThreshold int32
	mu            sync.RWMutex // protects slot retire (shrink) and grow; RLock protects stream assignment

	// Connection rotation limits.
	connLifetime time.Duration // max age of a connection before rotation
	connMaxBytes int64         // max bytes per connection before rotation

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
	ConnMaxBytes      int64         // max bytes per connection before rotation (0: default)
	Timeout           time.Duration
	DialContext       func(ctx context.Context, network, addr string) (net.Conn, error)
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
		ratio = 0.5
	}
	prioritySlots := int(float64(maxSlots) * ratio)
	if prioritySlots < 1 {
		prioritySlots = 1
	}
	if prioritySlots > maxSlots {
		prioritySlots = maxSlots
	}

	bulkThreshold := threshold * 2

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
	slots := make([]*transportSlot, maxSlots)
	for i := range slots {
		slots[i] = newSlot(cfg.TLSConfig, timeout, dialCtx)
	}

	tr := &HTTP2Transport{
		slots:         slots,
		maxSlots:      maxSlots,
		threshold:     threshold,
		prioritySlots: prioritySlots,
		bulkThreshold: bulkThreshold,
		connLifetime:  connLifetime,
		connMaxBytes:  connMaxBytes,
		serverURL:     cfg.ServerURL,
		ctx:           ctx,
		cancel:        cancel,
	}
	go tr.healthLoop()
	return tr, nil
}

func newSlot(utlsCfg *utls.Config, timeout time.Duration, dialContext func(context.Context, string, string) (net.Conn, error)) *transportSlot {
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
			// A new connection resets the rotation state: lifetime, bytes
			// carried and the expiring mark all start fresh.
			slot.connStart.Store(time.Now().UnixNano())
			slot.connBytesRecv.Store(0)
			slot.expiring.Store(false)
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

	t.maybeGrowSlots(req.HighPriority)

	t.mu.RLock()
	slot := t.selectSlot(req.HighPriority)
	slot.active.Add(1)
	if req.HighPriority {
		stats.RecordStreamOpenedPriority()
	} else {
		stats.RecordStreamOpenedBulk()
	}
	t.mu.RUnlock()

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

func (t *HTTP2Transport) selectSlot(highPriority bool) *transportSlot {
	if highPriority && t.prioritySlots > 0 {
		slot := t.leastActiveSlotRange(0, t.prioritySlots)
		if slot == nil || slot.active.Load() >= t.threshold {
			stats.RecordPriorityFallback()
			slot = t.leastActiveSlotRange(t.prioritySlots, int(t.liveCount.Load()))
		}
		return slot
	}

	slot := t.leastActiveSlotRange(t.prioritySlots, int(t.liveCount.Load()))
	if slot == nil || slot.active.Load() >= t.bulkThreshold {
		stats.RecordBulkFallback()
		slot = t.leastActiveSlotRange(0, t.prioritySlots)
	}
	return slot
}

func (t *HTTP2Transport) leastActiveSlotRange(start, end int) *transportSlot {
	live := int(t.liveCount.Load())
	if live == 0 {
		return t.slots[0]
	}
	if end > live {
		end = live
	}
	if start >= end {
		start = 0
		end = live
	}
	// Prefer healthy slots, then slots without heavy streams, and only fall
	// back to degraded or expiring ones when nothing else is available:
	//   - a heavy stream monopolizes the connection's TCP window, so a new
	//     stream sharing that slot is dragged down together with it (TCP
	//     head-of-line blocking under packet loss);
	//   - a degraded slot already proved persistently low throughput, so it
	//     is avoided unless it is the only option left;
	//   - an expiring slot is due for connection rotation, so new streams
	//     avoid it unless nothing else is available.
	passes := []struct {
		skipHeavy    bool
		skipDegraded bool
		skipExpiring bool
	}{
		{true, true, true},   // healthy slots
		{false, true, true},  // heavy but not degraded/expiring
		{false, false, true}, // degraded but not expiring
		{false, false, false},
	}
	var best *transportSlot
	for _, p := range passes {
		var min int32 = math.MaxInt32
		for i := start; i < end; i++ {
			s := t.slots[i]
			if p.skipHeavy && s.heavy.Load() > 0 {
				continue
			}
			if p.skipDegraded && s.degraded.Load() {
				continue
			}
			if p.skipExpiring && s.expiring.Load() {
				continue
			}
			if a := s.active.Load(); a < min {
				best, min = s, a
			}
		}
		if best != nil {
			return best
		}
	}
	return t.slots[0]
}

// maybeGrowSlots checks whether the live slots that a new stream would
// actually use are all at or above the threshold, and if so, activates one
// more slot (up to maxSlots). Uses double-checked locking.
func (t *HTTP2Transport) maybeGrowSlots(highPriority bool) {
	live := t.liveCount.Load()
	if int(live) >= t.maxSlots {
		return
	}

	thresh := t.threshold
	start, end := int32(0), live
	if highPriority && t.prioritySlots > 0 {
		end = int32(t.prioritySlots)
		if end > live {
			end = live
		}
	} else if t.prioritySlots > 0 {
		start = int32(t.prioritySlots)
		thresh = t.bulkThreshold
	}

	if live > 0 {
		if start >= end {
			return
		}
		if !t.shouldGrow(start, end, thresh) {
			return
		}
	}

	// All eligible slots in range are at or above threshold — try to grow
	// under lock.
	t.mu.Lock()
	defer t.mu.Unlock()

	// Double-check after acquiring the lock.
	live = t.liveCount.Load()
	if int(live) >= t.maxSlots {
		return
	}
	start2, end2 := int32(0), live
	if highPriority && t.prioritySlots > 0 {
		end2 = int32(t.prioritySlots)
		if end2 > live {
			end2 = live
		}
	} else if t.prioritySlots > 0 {
		start2 = int32(t.prioritySlots)
	}
	if live > 0 {
		if start2 >= end2 {
			return
		}
		if !t.shouldGrow(start2, end2, thresh) {
			return
		}
	}

	// On first activation, start with 2 connections for better initial throughput,
	// since typical web browsing generates >8 concurrent streams.
	// Falls back to 1 when maxSlots is 1.
	if live == 0 && t.maxSlots >= 2 {
		t.liveCount.Add(2)
	} else {
		t.liveCount.Add(1)
	}
}

// shouldGrow reports whether the range [start,end) needs one more live
// slot: every slot a new stream would actually use is at or above the
// threshold. Heavy, degraded and expiring slots are skipped — a new stream
// avoids them, so a heavy slot hosting a single download must not block
// growing more connections. A range with no eligible slot at all also
// grows, since new streams then fall back onto heavy/degraded slots and
// deserve a fresh connection.
func (t *HTTP2Transport) shouldGrow(start, end, thresh int32) bool {
	for i := start; i < end; i++ {
		s := t.slots[i]
		if s.heavy.Load() > 0 || s.degraded.Load() || s.expiring.Load() {
			continue
		}
		if s.active.Load() < thresh {
			return false
		}
	}
	return true
}

func (t *HTTP2Transport) CloseIdle() {
	// Close idle TCP connections on all slots (no lock needed).
	for _, s := range t.slots {
		s.t.CloseIdleConnections()
	}

	// Shrink liveCount by retiring idle slots (any position, swap-remove).
	t.mu.Lock()
	defer t.mu.Unlock()
	for t.shrinkIdleLocked() {
	}
}

// shrinkIdleLocked retires one idle slot (active==0) from liveCount,
// swap-removing it to the end. Caller must hold t.mu. Returns false when
// no idle slot remains.
func (t *HTTP2Transport) shrinkIdleLocked() bool {
	live := int(t.liveCount.Load())
	for i := 0; i < live; i++ {
		if t.slots[i].active.Load() != 0 {
			continue
		}
		last := live - 1
		if i != last {
			t.slots[i], t.slots[last] = t.slots[last], t.slots[i]
		}
		t.liveCount.Add(-1)
		return true
	}
	return false
}

// healthLoop periodically samples slot health: download throughput feeds
// the degraded detector, connection age/bytes feed rotation, and idle
// degraded slots are retired. It runs until the transport is closed
// (t.ctx cancelled).
func (t *HTTP2Transport) healthLoop() {
	interval := sharedconfig.HealthCheckInterval
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			t.evaluateHealth(interval)
		case <-t.ctx.Done():
			return
		}
	}
}

func (t *HTTP2Transport) evaluateHealth(interval time.Duration) {
	// A congested link (high RTT) makes every connection slow: marking or
	// retiring slots then only adds handshake churn without recovering
	// anything, so degraded detection is gated on a healthy RTT. Rotation,
	// on the other hand, is exactly what a throttled connection needs and
	// runs regardless of RTT.
	linkOK := stats.Collect().AvgRTT() <= sharedconfig.DegradedMaxRTT

	live := int(t.liveCount.Load())
	for i := 0; i < live; i++ {
		s := t.slots[i]
		t.evaluateSlotHealth(i, s, interval, linkOK)
		t.evaluateRotation(i, s)
		if linkOK && s.degraded.Load() && s.active.Load() == 0 {
			t.retireSlot(s)
			// retireSlot swap-removes the slot to the end and shrinks
			// liveCount; re-evaluate the slot swapped into position i.
			live--
			i--
		}
	}
}

// evaluateSlotHealth updates one slot's degraded state from its recent
// download throughput. Only slots hosting heavy streams are considered —
// idle or short-lived slots naturally carry zero throughput. The mark is
// set after DegradedPersistCycles consecutive slow intervals and cleared
// after DegradedRecoverCycles healthy ones.
func (t *HTTP2Transport) evaluateSlotHealth(idx int, s *transportSlot, interval time.Duration, linkOK bool) {
	if s.heavy.Load() == 0 {
		s.lastHeavy = 0
		return
	}
	if s.lastHeavy == 0 {
		// First heavy stream on this slot since it went idle: bytes
		// transferred by earlier small streams must not skew the first
		// sample, so reset the baseline and skip this interval.
		s.lastHeavy = 1
		s.lastBytes = s.bytesRecv.Load()
		s.lowCycles = 0
		s.recoverCycles = 0
		return
	}
	if !linkOK {
		// Congested link: low throughput is a link property, not evidence
		// that this particular connection is broken. Advance the baseline
		// so the first healthy interval starts from a clean sample, and
		// freeze the counters.
		s.lastBytes = s.bytesRecv.Load()
		return
	}

	now := s.bytesRecv.Load()
	perSec := int64(interval / time.Second)
	if perSec <= 0 {
		perSec = 1
	}
	throughput := (now - s.lastBytes) / perSec
	s.lastBytes = now

	if throughput >= int64(sharedconfig.DegradedThroughputThreshold) {
		s.lowCycles = 0
		if s.degraded.Load() {
			s.recoverCycles++
			if s.recoverCycles >= sharedconfig.DegradedRecoverCycles {
				s.degraded.Store(false)
				s.recoverCycles = 0
				log.Info("[TRANSPORT] slot recovered", "slot", idx, "throughput_kb_s", throughput/1024)
			}
		}
		return
	}

	s.recoverCycles = 0
	s.lowCycles++
	if s.lowCycles >= sharedconfig.DegradedPersistCycles && !s.degraded.Load() {
		s.degraded.Store(true)
		s.lowCycles = 0
		stats.RecordSlotDegraded()
		log.Info("[TRANSPORT] slot degraded", "slot", idx, "throughput_kb_s", throughput/1024)
	}
}

// evaluateRotation marks a slot expiring once its connection exceeded the
// lifetime or bytes limit, and completes the rotation once the slot goes
// idle: the tired connection is closed so the next stream dials a fresh
// one. In-flight streams are never interrupted.
func (t *HTTP2Transport) evaluateRotation(idx int, s *transportSlot) {
	if s.expiring.Load() {
		if s.active.Load() == 0 {
			s.t.CloseIdleConnections()
			s.expiring.Store(false)
			stats.RecordConnRotated()
			log.Info("[TRANSPORT] connection rotated", "slot", idx)
		}
		return
	}
	if t.rotationDue(s, time.Now()) {
		s.expiring.Store(true)
		log.Info("[TRANSPORT] slot connection expiring", "slot", idx)
	}
}

// rotationDue reports whether the slot's connection exceeded the lifetime
// or bytes limit and should stop accepting new streams.
func (t *HTTP2Transport) rotationDue(s *transportSlot, now time.Time) bool {
	if t.connLifetime > 0 {
		if start := s.connStart.Load(); start > 0 && now.Sub(time.Unix(0, start)) >= t.connLifetime {
			return true
		}
	}
	if t.connMaxBytes > 0 && s.connBytesRecv.Load() >= t.connMaxBytes {
		return true
	}
	return false
}

// retireSlot closes a degraded slot's idle connection and shrinks liveCount
// once the slot no longer hosts any stream. Streams are re-checked under
// the lock so a concurrent Open cannot be stranded.
func (t *HTTP2Transport) retireSlot(s *transportSlot) {
	s.t.CloseIdleConnections()
	t.mu.Lock()
	defer t.mu.Unlock()
	if s.active.Load() != 0 {
		return
	}
	live := int(t.liveCount.Load())
	for i := 0; i < live; i++ {
		if t.slots[i] != s {
			continue
		}
		last := live - 1
		if i != last {
			t.slots[i], t.slots[last] = t.slots[last], t.slots[i]
		}
		t.liveCount.Add(-1)
		stats.RecordSlotRetiredDegraded()
		log.Info("[TRANSPORT] slot retired (degraded)", "slot", i)
		return
	}
}

func (t *HTTP2Transport) Stats() transport.TransportStats {
	live := int(t.liveCount.Load())
	ts := transport.TransportStats{
		Conns: live,
	}
	pConns := t.prioritySlots
	if live < pConns {
		pConns = live
	}
	ts.PriorityConns = pConns
	ts.BulkConns = live - pConns

	for i := int32(0); i < int32(live); i++ {
		a := int(t.slots[i].active.Load())
		ts.ActiveStreams += a
		if i < int32(t.prioritySlots) {
			ts.PriorityActiveStreams += a
		} else {
			ts.BulkActiveStreams += a
		}
	}
	return ts
}

func (t *HTTP2Transport) Close() error {
	t.cancel()
	live := t.liveCount.Load()
	for _, s := range t.slots[:live] {
		s.t.CloseIdleConnections()
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
