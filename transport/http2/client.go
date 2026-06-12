package http2

import (
	"context"
	"io"
	"math"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	utls "github.com/refraction-networking/utls"

	"github.com/nange/easyss/v3/transport"
)

type transportSlot struct {
	t      *http.Transport
	active atomic.Int32
}

type HTTP2Transport struct {
	slots     []*transportSlot
	serverURL string
	ctx       context.Context
	cancel    context.CancelFunc
	mu        sync.RWMutex
}

type Config struct {
	ServerURL string
	TLSConfig *utls.Config
	SlotCount int
	Timeout   time.Duration
}

func New(cfg Config) (*HTTP2Transport, error) {
	slotCount := cfg.SlotCount
	if slotCount < 1 {
		slotCount = 8
	}

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	ctx, cancel := context.WithCancel(context.Background())

	slots := make([]*transportSlot, slotCount)
	for i := range slots {
		slots[i] = newSlot(cfg.TLSConfig, timeout)
	}

	return &HTTP2Transport{
		slots:     slots,
		serverURL: cfg.ServerURL,
		ctx:       ctx,
		cancel:    cancel,
	}, nil
}

func newSlot(utlsCfg *utls.Config, timeout time.Duration) *transportSlot {
	tr := &http.Transport{
		Protocols: &http.Protocols{},
		HTTP2: &http.HTTP2Config{
			SendPingTimeout:  15 * time.Second,
			WriteByteTimeout: timeout / 2,
		},
		ForceAttemptHTTP2: true,
		MaxConnsPerHost:   1,
		IdleConnTimeout:   4 * timeout,
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialer := &net.Dialer{Timeout: timeout}
			tcpConn, err := dialer.DialContext(ctx, network, addr)
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
			return uconn, nil
		},
	}
	tr.Protocols.SetHTTP2(true)
	return &transportSlot{t: tr}
}

func (t *HTTP2Transport) Open(ctx context.Context, req transport.OpenRequest) (transport.Stream, error) {
	if t.ctx.Err() != nil {
		return nil, t.ctx.Err()
	}

	slot := t.leastActiveSlot()
	slot.active.Add(1)

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
		pw.Close()
		cancel()
		slot.active.Add(-1)
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/octet-stream")
	httpReq.Header.Set("Cache-Control", "no-store")
	if req.Salt != "" {
		httpReq.Header.Set("x-es", req.Salt)
	}

	respCh := make(chan roundTripResult, 1)
	go func() {
		resp, err := slot.t.RoundTrip(httpReq)
		if err != nil {
			_ = pw.CloseWithError(err)
		}
		respCh <- roundTripResult{resp: resp, err: err}
	}()

	doneOnce := sync.OnceFunc(func() { slot.active.Add(-1) })

	return &HTTP2Stream{
		w:      pw,
		respCh: respCh,
		cancel: cancel,
		done:   doneOnce,
	}, nil
}

func (t *HTTP2Transport) leastActiveSlot() *transportSlot {
	var best *transportSlot
	var min int32 = math.MaxInt32
	for _, s := range t.slots {
		if a := s.active.Load(); a < min {
			best, min = s, a
		}
	}
	return best
}

func (t *HTTP2Transport) CloseIdle() {
	for _, s := range t.slots {
		s.t.CloseIdleConnections()
	}
}

func (t *HTTP2Transport) Stats() transport.TransportStats {
	stats := transport.TransportStats{
		ConnCount: len(t.slots),
	}
	for _, s := range t.slots {
		stats.ActiveStream += int(s.active.Load())
	}
	return stats
}

func (t *HTTP2Transport) Close() error {
	t.cancel()
	for _, s := range t.slots {
		s.t.CloseIdleConnections()
	}
	return nil
}

var _ transport.Transport = (*HTTP2Transport)(nil)
