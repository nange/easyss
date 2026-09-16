package handler

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"runtime/debug"

	sharedconfig "github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/crypto"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/protocol"
	"github.com/nange/easyss/v3/shaper"
	"github.com/nange/easyss/v3/stats"
	"github.com/nange/easyss/v3/util"
)

// serveReject writes a bare HTTP error response for handshake rejections.
// Unlike ServeFallback it sends no camouflaged HTML body: it is only used for
// requests that either timed out waiting for the handshake record, or already
// proved master-key possession by sending a valid encrypted handshake — for
// those, 4xx/5xx statuses are both realistic and distinguishable for the
// easyss client, which checks the status code before reading the body.
func serveReject(w http.ResponseWriter, code int) {
	w.WriteHeader(code)
}

// handshakeResult carries the state a validated handshake passes to
// serveSession.
type handshakeResult struct {
	sk       *crypto.StreamKeys
	first    crypto.FirstRecord
	endpoint string
	target   string
	method   protocol.Method
}

// ServeHTTP serves one request: everything that can reject the handshake
// before the response is committed (preflight), then the encrypted session
// itself (serveSession).
func (h *ProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if e := recover(); e != nil {
			log.Error("[SERVER] handler panic", "remote", r.RemoteAddr, "target", r.URL.Path, "panic", fmt.Sprint(e), "stack", string(debug.Stack()))
			_ = http.NewResponseController(w).Flush()
		}
	}()

	res, ok := h.preflight(w, r)
	if !ok {
		return
	}
	h.serveSession(w, r, res)
}

// preflight runs every check that can reject the request with a fallback page
// or a bare 4xx/5xx, all before the response is committed (once the
// octet-stream headers are flushed the response can no longer turn into a
// fallback HTML page). ok=false means the response has been written and
// ServeHTTP must return.
func (h *ProxyHandler) preflight(w http.ResponseWriter, r *http.Request) (handshakeResult, bool) {
	if !r.ProtoAtLeast(2, 0) {
		ServeFallback(w, r)
		return handshakeResult{}, false
	}

	// The proxy endpoints only ever carry a POST body (the bootstrap
	// record). Non-POST requests (GET/HEAD/OPTIONS probes) must not enter
	// the handshake path: they would burn salt-cache entries and rate-limit
	// budget while producing nothing.
	if r.Method != http.MethodPost {
		ServeFallback(w, r)
		return handshakeResult{}, false
	}

	saltB64 := r.Header.Get("x-es")
	if saltB64 == "" {
		ServeFallback(w, r)
		return handshakeResult{}, false
	}

	salt, err := base64.RawURLEncoding.DecodeString(saltB64)
	if err != nil || len(salt) != 16 {
		ServeFallback(w, r)
		return handshakeResult{}, false
	}

	// Bound handshake attempts per source IP to mitigate replay storms and
	// CPU abuse. Only counted for requests that look like a real handshake
	// (valid x-es header), so plain fallback-page traffic is unaffected.
	if !h.ipLimiter.Allow(clientIP(r)) {
		// Debug, not Error: any peer that sends a well-formed x-es header
		// reaches this branch, so an unauthenticated IP-churning client could
		// otherwise flood the log. The limiter warns once per cleanup interval
		// when its hard cap is hit.
		log.Debug("[SERVER] handshake rate limited", "remote", r.RemoteAddr)
		stats.RecordServerHandshakeError()
		serveReject(w, http.StatusTooManyRequests)
		return handshakeResult{}, false
	}

	// Reject replayed bootstrap records. Every stream uses a unique random
	// salt; a salt already accepted by this server means the record is being
	// re-delivered (replay), and accepting it would re-dial the target and
	// re-deliver the first packet. Replays carry a valid encrypted handshake,
	// so the responder has proven key possession and 400 is appropriate.
	if h.saltCache.MarkSeen(r.URL.Path, saltB64) {
		log.Debug("[SERVER] replayed salt", "remote", r.RemoteAddr, "endpoint", r.URL.Path)
		stats.RecordServerHandshakeError()
		serveReject(w, http.StatusBadRequest)
		return handshakeResult{}, false
	}

	endpoint := r.URL.Path
	sk, err := crypto.NewStreamKeys(h.masterKey, salt, endpoint)
	if err != nil {
		ServeFallback(w, r)
		return handshakeResult{}, false
	}

	first, err := sk.ReadFirstRecordWithTimeout(r.Context(), r.Body, h.handshakeTimeout)
	if err != nil {
		stats.RecordServerHandshakeError()
		if errors.Is(err, crypto.ErrHandshakeTimeout) {
			log.Warn("[SERVER] read first record timed out", "remote", r.RemoteAddr, "endpoint", endpoint, "err", err)
			// The client connected but its bootstrap record did not arrive in
			// time (congested link, connection dying). A real HTTP/2 site
			// (nginx) answers a late/absent request body with 408 Request
			// Timeout; serving the camouflaged homepage here would poison the
			// legit client's record stream with HTML. 408 lets the client fail
			// fast and cleanly instead of misparsing the page as records.
			serveReject(w, http.StatusRequestTimeout)
			return handshakeResult{}, false
		}
		// Decrypt failure: the request did not prove master-key possession
		// (attacker probing, wrong key). Debug, not Error: any request with a
		// random x-es header reaches this branch, and error-level logging here
		// lets an unauthenticated peer flood the log. Keep the camouflaged
		// homepage so the server stays indistinguishable from a real site for
		// keyless requests; the easyss client detects the non-encrypted payload
		// on its first session read and reports a clear handshake-rejected
		// error.
		log.Debug("[SERVER] read first record failed", "remote", r.RemoteAddr, "endpoint", endpoint, "err", err)
		ServeFallback(w, r)
		return handshakeResult{}, false
	}

	if !first.Handshake.MatchesEndpoint(endpoint) {
		log.Error("[SERVER] endpoint mismatch", "remote", r.RemoteAddr, "proto", first.Handshake.Proto.String(), "endpoint", endpoint)
		stats.RecordServerHandshakeError()
		serveReject(w, http.StatusNotFound)
		return handshakeResult{}, false
	}

	if !h.allowedMethods[first.Handshake.Method] {
		log.Error("[SERVER] method not allowed", "remote", r.RemoteAddr, "method", first.Handshake.Method.String())
		stats.RecordServerHandshakeError()
		serveReject(w, http.StatusMethodNotAllowed)
		return handshakeResult{}, false
	}

	target := first.Handshake.Target

	// Reject LAN/private targets to prevent SSRF attacks. This MUST happen
	// before the response is committed (WriteHeader + Flush): once the
	// octet-stream headers are flushed the response can no longer be turned
	// into a fallback HTML page, and the client would receive a 200
	// application/octet-stream instead of a clean rejection. IsLANHostResolved
	// also resolves domain names so a target like evil.com (which resolves to
	// 127.0.0.1) cannot bypass the literal-IP check.
	if util.IsLANHostResolved(r.Context(), target) {
		log.Error("[SERVER] rejected LAN target", "target", target, "remote", r.RemoteAddr)
		stats.RecordServerHandshakeError()
		serveReject(w, http.StatusBadRequest)
		return handshakeResult{}, false
	}

	return handshakeResult{
		sk:       sk,
		first:    first,
		endpoint: endpoint,
		target:   target,
		method:   first.Handshake.Method,
	}, true
}

// serveSession commits the encrypted session on the response and dispatches
// to the endpoint handler. Everything from the first WriteHeader on happens
// here: the response can no longer be turned into a fallback HTML page, so a
// failure after this point surfaces as a stream-level RST instead of an HTTP
// error.
func (h *ProxyHandler) serveSession(w http.ResponseWriter, r *http.Request, res handshakeResult) {
	log.Info("[SERVER] proxy", "target", res.target, "remote", r.RemoteAddr)

	// Pre-validate the session reader/writer before committing the response.
	// Once WriteHeader + Flush is called the response can no longer be
	// turned into a fallback HTML page. Reader/writer creation checks that
	// the method is supported (already validated in preflight), but we guard
	// against unexpected internal errors. The request proved key possession,
	// so a plain 500 (real-site behavior for internal failures) is
	// appropriate.
	s2cWriter, err := res.sk.NewWriter(w, crypto.DirS2C, res.method)
	if err != nil {
		log.Error("[SERVER] s2c writer", "err", err)
		serveReject(w, http.StatusInternalServerError)
		return
	}
	c2sReader, err := res.sk.NewReader(r.Body, crypto.DirC2S, res.method)
	if err != nil {
		log.Error("[SERVER] c2s reader", "err", err)
		serveReject(w, http.StatusInternalServerError)
		return
	}

	rc := http.NewResponseController(w)
	_ = rc.EnableFullDuplex()

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)

	_ = rc.Flush()

	c2sReader.SetLeftoverFrames(res.first.Leftover)

	s2cCfg := h.shaperCfg
	if res.endpoint == sharedconfig.EndpointUDP {
		// UDP uses a short 1ms batch window so datagram bursts are merged
		// into single encrypted records instead of one record + forced
		// HTTP/2 flush per datagram.
		s2cCfg.BatchWindowMS = 1
	}
	s2cShaper := shaper.New(s2cWriter, s2cCfg)
	defer s2cShaper.Close() //nolint:errcheck

	var handleErr error
	switch res.endpoint {
	case sharedconfig.EndpointTCP:
		stats.RecordServerTCPStream()
		// cancelRead unblocks the relay's client-read goroutine immediately
		// when the relay terminates (idle timeout/error), instead of letting
		// it linger on the request body until net/http closes it.
		handleErr = h.tcp.Handle(r.Context(), c2sReader, s2cShaper, res.target, func() { _ = r.Body.Close() })
	case sharedconfig.EndpointUDP:
		stats.RecordServerUDPStream()
		// cancelRead unblocks the client-read goroutine immediately when the
		// UDP handler terminates, mirroring the TCP path: without it the
		// frame reader lingers on the request body until net/http closes it
		// after ServeHTTP returns.
		handleErr = h.udp.Handle(r.Context(), c2sReader, s2cShaper, res.target, func() { _ = r.Body.Close() })
	case sharedconfig.EndpointICMP:
		stats.RecordServerICMPStream()
		handleErr = h.icmp.Handle(c2sReader, s2cShaper, res.target)
	}
	if handleErr != nil {
		log.Info("[SERVER] handler finished with error", "target", res.target, "endpoint", res.endpoint, "err", handleErr)
	} else {
		log.Debug("[SERVER] handler finished", "target", res.target, "endpoint", res.endpoint)
	}
}
