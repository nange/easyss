package http2

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"

	sharedconfig "github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/crypto"
	"github.com/nange/easyss/v3/server/handler"
)

const testProbePayloadSize = 4096

// newProbeServer starts a real TLS server serving the probe endpoint.
func newProbeServer(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	masterKey, err := crypto.DeriveMasterKey("test-password")
	if err != nil {
		t.Fatal(err)
	}
	token, err := crypto.ProbeToken(masterKey)
	if err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, testProbePayloadSize)
	for i := range payload {
		payload[i] = byte(i)
	}
	h, err := handler.NewProbeHandler(masterKey, payload)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewUnstartedServer(h)
	ts.EnableHTTP2 = true
	ts.StartTLS()
	t.Cleanup(ts.Close)
	return ts, token
}

// newProbeSlot builds a slot whose transport talks plain TLS to the test
// server (the production transport uses uTLS, which is irrelevant here).
func newProbeSlot() *transportSlot {
	tr := &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // test server cert
		ForceAttemptHTTP2: true,
		MaxConnsPerHost:   1,
	}
	return &transportSlot{t: tr}
}

func TestSlotProberFast(t *testing.T) {
	ts, token := newProbeServer(t)
	prober := &slotProber{serverURL: ts.URL, token: token, payloadSize: testProbePayloadSize}

	speed, verdict := prober.probe(context.Background(), newProbeSlot())

	if verdict != probeFast {
		t.Fatalf("verdict = %v, want probeFast (speed %v)", verdict, speed)
	}
	if speed < float64(sharedconfig.DegradedThroughputThreshold) {
		t.Fatalf("speed %v below the degraded threshold", speed)
	}
}

func TestSlotProberSlowOnEmptyBody(t *testing.T) {
	// A 200 octet-stream response that delivers nothing within the probe
	// timeout counts as slow evidence.
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", "4096")
		w.WriteHeader(http.StatusOK)
		_ = http.NewResponseController(w).Flush()
	}))
	t.Cleanup(ts.Close)
	prober := &slotProber{serverURL: ts.URL, token: "unused", payloadSize: testProbePayloadSize}

	speed, verdict := prober.probe(context.Background(), newProbeSlot())

	if verdict != probeSlow {
		t.Fatalf("verdict = %v, want probeSlow (speed %v)", verdict, speed)
	}
	if speed != 0 {
		t.Fatalf("speed = %v, want 0", speed)
	}
}

func TestSlotProberUnsupportedOnHTML(t *testing.T) {
	// A 200 page that is not the probe payload (e.g. an old server's
	// fallback HTML) marks the probe unsupported.
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("<html><body>fallback</body></html>"))
	}))
	t.Cleanup(ts.Close)
	prober := &slotProber{serverURL: ts.URL, token: "unused", payloadSize: testProbePayloadSize}

	_, verdict := prober.probe(context.Background(), newProbeSlot())

	if verdict != probeUnsupported {
		t.Fatalf("verdict = %v, want probeUnsupported", verdict)
	}
}

func TestSlotProberInconclusiveOnErrorStatus(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
	}))
	t.Cleanup(ts.Close)
	prober := &slotProber{serverURL: ts.URL, token: "unused", payloadSize: testProbePayloadSize}

	_, verdict := prober.probe(context.Background(), newProbeSlot())

	if verdict != probeInconclusive {
		t.Fatalf("verdict = %v, want probeInconclusive", verdict)
	}
}

func TestSlotProberInconclusiveOnDialError(t *testing.T) {
	ts, _ := newProbeServer(t)
	deadURL := ts.URL
	ts.Close() // connection refused from now on

	prober := &slotProber{serverURL: deadURL, token: "unused", payloadSize: testProbePayloadSize}

	_, verdict := prober.probe(context.Background(), newProbeSlot())

	if verdict != probeInconclusive {
		t.Fatalf("verdict = %v, want probeInconclusive", verdict)
	}
}
