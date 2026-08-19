package handler

import (
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"strconv"

	"github.com/nange/easyss/v3/crypto"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/stats"
)

// probeChunkSize is the write granularity for the probe payload: each chunk
// is flushed so the payload reaches the client at its real network pace
// instead of being buffered server-side.
const probeChunkSize = 32 * 1024

// ProbeHandler serves the pre-generated random payload used by clients to
// actively measure the download throughput of their own connection. A valid
// request must carry the capability token derived from the master key in the
// x-es header (same header name and wire shape as the proxy handshake salt);
// anything else is answered with the camouflaged fallback page so the server
// stays indistinguishable from a real site.
type ProbeHandler struct {
	payload []byte
	token   []byte
	limiter *ipRateLimiter
}

// NewProbeHandler builds the /v3/probe handler. The payload must have been
// generated at server startup; serving the same buffer keeps the endpoint
// cheap and uncacheable (Cache-Control: no-store).
func NewProbeHandler(masterKey, payload []byte) (*ProbeHandler, error) {
	tokenB64, err := crypto.ProbeToken(masterKey)
	if err != nil {
		return nil, err
	}
	token, err := base64.RawURLEncoding.DecodeString(tokenB64)
	if err != nil {
		return nil, err
	}
	return &ProbeHandler{
		payload: payload,
		token:   token,
		limiter: newIPRateLimiter(),
	}, nil
}

func (h *ProbeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !r.ProtoAtLeast(2, 0) {
		ServeFallback(w, r)
		return
	}

	tokenB64 := r.Header.Get("x-es")
	if tokenB64 == "" {
		ServeFallback(w, r)
		return
	}
	token, err := base64.RawURLEncoding.DecodeString(tokenB64)
	if err != nil || len(token) != len(h.token) ||
		subtle.ConstantTimeCompare(token, h.token) != 1 {
		ServeFallback(w, r)
		return
	}

	// Bound probe downloads per source IP; wrong-token requests never reach
	// this point (they get the cheap fallback page instead).
	if !h.limiter.Allow(clientIP(r)) {
		log.Error("[SERVER] probe rate limited", "remote", r.RemoteAddr)
		serveReject(w, http.StatusTooManyRequests)
		return
	}

	stats.RecordServerProbe()

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Length", strconv.Itoa(len(h.payload)))
	w.WriteHeader(http.StatusOK)

	rc := http.NewResponseController(w)
	_ = rc.Flush()

	for off := 0; off < len(h.payload); off += probeChunkSize {
		end := min(off+probeChunkSize, len(h.payload))
		if _, err := w.Write(h.payload[off:end]); err != nil {
			return
		}
		_ = rc.Flush()
	}
}
