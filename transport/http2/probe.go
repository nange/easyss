package http2

import (
	"context"
	"net/http"
	"time"

	sharedconfig "github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/stats"
)

// probeVerdict classifies a single probe result.
type probeVerdict int

const (
	// probeInconclusive: the probe failed before any body bytes arrived
	// (RoundTrip error, non-200 status): the connection is either dead
	// (handled by stream errors/rotation) or transiently rejected (429),
	// so no verdict is produced.
	probeInconclusive probeVerdict = iota
	// probeFast: the payload was delivered at or above the degraded
	// throughput threshold.
	probeFast
	// probeSlow: no bytes arrived within the probe timeout, or the body
	// throughput stayed below the degraded threshold.
	probeSlow
	// probeUnsupported: the server answered 200 but not with the probe
	// payload (wrong Content-Type/Content-Length), i.e. it does not serve
	// the /v3/probe endpoint and the client must fall back to passive
	// detection.
	probeUnsupported
)

// maxProbeSpeed caps the measured throughput so a single instantaneous
// (elapsed==0) probe cannot latch the link reference speed to an absurd
// value.
const maxProbeSpeed = 1 << 30 // 1GB/s

// slotProber actively measures the download throughput of one slot's own
// connection by downloading the server's pre-generated random payload
// through the slot's http.Transport (MaxConnsPerHost=1 pins the transport
// to that single connection, so the probe bytes traverse exactly the
// connection under test).
type slotProber struct {
	serverURL   string
	token       string
	payloadSize int64
}

// probe downloads the probe payload over the slot's connection and reports
// the body throughput (excluding TTFB: timing starts with the first body
// chunk). The verdict is decided against the absolute degraded threshold;
// the lifecycle applies the link-reference refinement on top.
func (p *slotProber) probe(ctx context.Context, slot *transportSlot) (float64, probeVerdict) {
	probeCtx, cancel := context.WithTimeout(ctx, sharedconfig.ProbeTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(probeCtx, http.MethodGet, p.serverURL+sharedconfig.EndpointProbe, nil)
	if err != nil {
		return 0, probeInconclusive
	}
	req.Header.Set("x-es", p.token)
	req.Header.Set("Cache-Control", "no-store")
	req.Header.Set("User-Agent", chromeUserAgent())

	resp, err := slot.t.RoundTrip(req)
	if err != nil {
		// RoundTrip failed (dial/TLS/stream error, or the timeout expired
		// before the response headers): the connection is dead or the
		// server is unreachable — no verdict, stream errors and rotation
		// handle those. A healthy redial inside RoundTrip completes the
		// request, so a fresh connection is never misjudged as slow.
		return 0, probeInconclusive
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		// Rejection (e.g. 429 rate limit): transient, re-probe later.
		return 0, probeInconclusive
	}
	if resp.ContentLength != p.payloadSize ||
		resp.Header.Get("Content-Type") != "application/octet-stream" {
		// The server answered 200 but not with the probe payload (e.g. a
		// fallback HTML page from a server without /v3/probe).
		return 0, probeUnsupported
	}

	buf := make([]byte, 32*1024)
	var total int64
	var start time.Time
	timed := false
	ttfbStart := time.Now()
	for {
		n, rErr := resp.Body.Read(buf)
		if n > 0 {
			total += int64(n)
			if !timed {
				timed = true
				start = time.Now()
				// The response headers have arrived and the server writes the
				// payload immediately (no origin involved), so the time to the
				// first body chunk is the pure path RTT — same measurement
				// basis as the per-request bootstrap round trip.
				stats.RecordRTT(time.Since(ttfbStart))
			}
		}
		if rErr != nil {
			break // EOF, timeout or connection error: measure what arrived
		}
	}

	if total == 0 {
		// Nothing arrived within the probe timeout (or the body was cut
		// short immediately): on any sane link the first bytes of 128KB
		// arrive well within 3s, so treat this as slow evidence.
		return 0, probeSlow
	}

	var speed float64 = maxProbeSpeed
	if elapsed := time.Since(start); elapsed > 0 {
		speed = float64(total) / elapsed.Seconds()
		if speed > maxProbeSpeed {
			speed = maxProbeSpeed
		}
	}
	if speed < float64(sharedconfig.DegradedThroughputThreshold) {
		return speed, probeSlow
	}
	return speed, probeFast
}
