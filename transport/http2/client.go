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
	"github.com/nange/easyss/v3/stats"
	"github.com/nange/easyss/v3/transport"
)

type transportSlot struct {
	t      *http.Transport
	active atomic.Int32
}

type HTTP2Transport struct {
	slots         []*transportSlot // pre-allocated and initialized to maxSlots
	liveCount     atomic.Int32     // number of currently active slots (0..maxSlots)
	maxSlots      int
	threshold     int32
	prioritySlots int // number of priority slots (0..prioritySlots-1)
	bulkThreshold int32
	mu            sync.RWMutex // protects slot retire (shrink) and grow; RLock protects stream assignment

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

	bulkThreshold := threshold * 3 / 2

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	dialCtx := cfg.DialContext
	if dialCtx == nil {
		dialCtx = defaultDialContext
	}

	ctx, cancel := context.WithCancel(context.Background())

	// Pre-allocate and initialize all slots. Transports are cheap structs;
	// actual TCP connections are established lazily by Go's http.Transport.
	slots := make([]*transportSlot, maxSlots)
	for i := range slots {
		slots[i] = newSlot(cfg.TLSConfig, timeout, dialCtx)
	}

	return &HTTP2Transport{
		slots:         slots,
		maxSlots:      maxSlots,
		threshold:     threshold,
		prioritySlots: prioritySlots,
		bulkThreshold: bulkThreshold,
		serverURL:     cfg.ServerURL,
		ctx:           ctx,
		cancel:        cancel,
	}, nil
}

func newSlot(utlsCfg *utls.Config, timeout time.Duration, dialContext func(context.Context, string, string) (net.Conn, error)) *transportSlot {
	if dialContext == nil {
		dialContext = defaultDialContext
	}

	protos := &http.Protocols{}
	protos.SetHTTP2(true)
	protos.SetUnencryptedHTTP2(true)

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			NextProtos: []string{"h2"},
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
			return uconn, nil
		},
	}
	return &transportSlot{t: tr}
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

	doneOnce := sync.OnceFunc(func() {
		slot.active.Add(-1)
		stats.RecordStreamClosed()
		cancel()
	})

	stream := &HTTP2Stream{
		w:      pw,
		respCh: respCh,
		cancel: cancel,
		done:   doneOnce,
	}

	go func() {
		resp, err := slot.t.RoundTrip(httpReq)
		if err != nil {
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
	var best *transportSlot
	var min int32 = math.MaxInt32
	for i := start; i < end; i++ {
		if a := t.slots[i].active.Load(); a < min {
			best, min = t.slots[i], a
		}
	}
	if best == nil {
		return t.slots[0]
	}
	return best
}

// maybeGrowSlots checks whether all live slots are at or above the threshold,
// and if so, activates one more slot (up to maxSlots). Uses double-checked locking.
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
		for i := start; i < end; i++ {
			if t.slots[i].active.Load() < thresh {
				return
			}
		}
	}

	// All slots in range are at or above threshold — try to grow under lock.
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
		for i := start2; i < end2; i++ {
			if t.slots[i].active.Load() < thresh {
				return
			}
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

func (t *HTTP2Transport) CloseIdle() {
	// Close idle TCP connections on all slots (no lock needed).
	for _, s := range t.slots {
		s.t.CloseIdleConnections()
	}

	// Shrink liveCount by retiring idle slots (any position, swap-remove).
	t.mu.Lock()
	defer t.mu.Unlock()
	for {
		live := int(t.liveCount.Load())
		if live == 0 {
			break
		}
		// Find first idle slot.
		retired := -1
		for i := 0; i < live; i++ {
			if t.slots[i].active.Load() == 0 {
				retired = i
				break
			}
		}
		if retired < 0 {
			break // no idle slots left
		}
		// Swap-remove: move idle slot to the end, then shrink.
		last := live - 1
		if retired != last {
			t.slots[retired], t.slots[last] = t.slots[last], t.slots[retired]
		}
		t.liveCount.Add(-1)
	}
}

func (t *HTTP2Transport) Stats() transport.TransportStats {
	live := int(t.liveCount.Load())
	ts := transport.TransportStats{
		ConnCount: live,
	}
	pConns := t.prioritySlots
	if live < pConns {
		pConns = live
	}
	ts.PriorityConnCount = pConns
	ts.BulkConnCount = live - pConns

	for i := int32(0); i < int32(live); i++ {
		a := int(t.slots[i].active.Load())
		ts.ActiveStream += a
		if i < int32(t.prioritySlots) {
			ts.PriorityActiveStream += a
		} else {
			ts.BulkActiveStream += a
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
