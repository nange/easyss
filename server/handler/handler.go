package handler

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"runtime/debug"
	"time"

	sharedconfig "github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/crypto"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/protocol"
	"github.com/nange/easyss/v3/server/nextproxy"
	"github.com/nange/easyss/v3/shaper"
	"github.com/nange/easyss/v3/stats"
	"github.com/nange/easyss/v3/util"
)

type ProxyHandler struct {
	masterKey        []byte
	allowedMethods   map[protocol.Method]bool
	handshakeTimeout time.Duration
	batchWindowMS    int
	coverBudgetRatio float64
	coverBudgetCap   int
	nextProxy        *nextproxy.NextProxy
	tcpHandler       *TCPHandler
	udpHandler       *UDPHandler
	icmpHandler      *ICMPHandler
	saltCache        *saltCache
	ipLimiter        *ipRateLimiter
}

type ProxyHandlerConfig struct {
	MasterKey         []byte
	AllowedMethods    []string
	HandshakeTimeout  time.Duration
	Timeout           time.Duration
	StreamIdleTimeout time.Duration
	UDPIdleTimeout    time.Duration
	BatchWindowMS     int
	CoverBudgetRatio  float64
	CoverBudgetCap    int
	NextProxy         *nextproxy.NextProxy
}

func NewProxyHandler(cfg ProxyHandlerConfig) *ProxyHandler {
	allowed := make(map[protocol.Method]bool)
	for _, m := range cfg.AllowedMethods {
		method := protocol.MethodFromString(m)
		if method != 0 {
			allowed[method] = true
		}
	}
	if len(allowed) == 0 {
		allowed[protocol.MethodAES256GCM] = true
		allowed[protocol.MethodChaCha20Poly1305] = true
	}

	batchWindowMS := cfg.BatchWindowMS
	if batchWindowMS <= 0 {
		batchWindowMS = sharedconfig.DefaultBatchWindowMS
	}
	if batchWindowMS > 10 {
		batchWindowMS = 10
	}

	coverBudgetRatio := cfg.CoverBudgetRatio
	if coverBudgetRatio <= 0 || coverBudgetRatio > 1 {
		coverBudgetRatio = 0.03
	}

	coverBudgetCap := cfg.CoverBudgetCap
	if coverBudgetCap <= 0 {
		coverBudgetCap = sharedconfig.DefaultCoverBudgetCap
	}

	return &ProxyHandler{
		masterKey:        cfg.MasterKey,
		allowedMethods:   allowed,
		handshakeTimeout: cfg.HandshakeTimeout,
		batchWindowMS:    batchWindowMS,
		coverBudgetRatio: coverBudgetRatio,
		coverBudgetCap:   coverBudgetCap,
		nextProxy:        cfg.NextProxy,
		tcpHandler:       NewTCPHandler(cfg.StreamIdleTimeout, cfg.Timeout, cfg.NextProxy),
		udpHandler:       NewUDPHandler(cfg.UDPIdleTimeout, cfg.NextProxy),
		icmpHandler:      NewICMPHandler(),
		saltCache:        newSaltCache(),
		ipLimiter:        newIPRateLimiter(),
	}
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// serveReject writes a bare HTTP error response for handshake rejections.
// Unlike ServeFallback it sends no camouflaged HTML body: it is only used for
// requests that either timed out waiting for the handshake record, or already
// proved master-key possession by sending a valid encrypted handshake — for
// those, 4xx/5xx statuses are both realistic and distinguishable for the
// easyss client, which checks the status code before reading the body.
func serveReject(w http.ResponseWriter, code int) {
	w.WriteHeader(code)
}

func (h *ProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if e := recover(); e != nil {
			log.Error("[SERVER] handler panic", "remote", r.RemoteAddr, "target", r.URL.Path, "panic", fmt.Sprint(e), "stack", string(debug.Stack()))
			_ = http.NewResponseController(w).Flush()
		}
	}()

	if !r.ProtoAtLeast(2, 0) {
		ServeFallback(w, r)
		return
	}

	saltB64 := r.Header.Get("x-es")
	if saltB64 == "" {
		ServeFallback(w, r)
		return
	}

	salt, err := base64.RawURLEncoding.DecodeString(saltB64)
	if err != nil || len(salt) != 16 {
		ServeFallback(w, r)
		return
	}

	// Bound handshake attempts per source IP to mitigate replay storms and
	// CPU abuse. Only counted for requests that look like a real handshake
	// (valid x-es header), so plain fallback-page traffic is unaffected.
	if !h.ipLimiter.Allow(clientIP(r)) {
		log.Error("[SERVER] handshake rate limited", "remote", r.RemoteAddr)
		stats.RecordServerHandshakeError()
		serveReject(w, http.StatusTooManyRequests)
		return
	}

	// Reject replayed bootstrap records. Every stream uses a unique random
	// salt; a salt already accepted by this server means the record is being
	// re-delivered (replay), and accepting it would re-dial the target and
	// re-deliver the first packet. Replays carry a valid encrypted handshake,
	// so the responder has proven key possession and 400 is appropriate.
	if h.saltCache.MarkSeen(saltB64) {
		log.Error("[SERVER] replayed salt", "remote", r.RemoteAddr, "endpoint", r.URL.Path)
		stats.RecordServerHandshakeError()
		serveReject(w, http.StatusBadRequest)
		return
	}

	endpoint := r.URL.Path
	sk, err := crypto.NewStreamKeys(h.masterKey, salt, endpoint)
	if err != nil {
		ServeFallback(w, r)
		return
	}

	first, err := sk.ReadFirstRecordWithTimeout(r.Context(), r.Body, h.handshakeTimeout)
	if err != nil {
		log.Error("[SERVER] read first record", "remote", r.RemoteAddr, "endpoint", endpoint, "err", err)
		stats.RecordServerHandshakeError()
		if errors.Is(err, crypto.ErrHandshakeTimeout) {
			// The client connected but its bootstrap record did not arrive in
			// time (congested link, connection dying). A real HTTP/2 site
			// (nginx) answers a late/absent request body with 408 Request
			// Timeout; serving the camouflaged homepage here would poison the
			// legit client's record stream with HTML. 408 lets the client fail
			// fast and cleanly instead of misparsing the page as records.
			serveReject(w, http.StatusRequestTimeout)
			return
		}
		// Decrypt failure: the request did not prove master-key possession
		// (attacker probing, wrong key). Keep the camouflaged homepage so the
		// server stays indistinguishable from a real site for keyless
		// requests; the easyss client detects the non-encrypted payload on
		// its first session read and reports a clear handshake-rejected error.
		ServeFallback(w, r)
		return
	}

	if !first.Handshake.MatchesEndpoint(endpoint) {
		log.Error("[SERVER] endpoint mismatch", "remote", r.RemoteAddr, "proto", first.Handshake.Proto.String(), "endpoint", endpoint)
		stats.RecordServerHandshakeError()
		serveReject(w, http.StatusNotFound)
		return
	}

	if !h.allowedMethods[first.Handshake.Method] {
		log.Error("[SERVER] method not allowed", "remote", r.RemoteAddr, "method", first.Handshake.Method.String())
		stats.RecordServerHandshakeError()
		serveReject(w, http.StatusMethodNotAllowed)
		return
	}

	log.Info("[SERVER] proxy", "target", first.Handshake.Target, "remote", r.RemoteAddr)

	target := first.Handshake.Target
	method := first.Handshake.Method

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
		return
	}

	// Pre-validate session encryptors before committing the response.
	// Once WriteHeader + Flush is called the response can no longer be
	// turned into a fallback HTML page. Encryptor creation checks that the
	// method is supported (already validated above), but we guard against
	// unexpected internal errors. The request proved key possession, so a
	// plain 500 (real-site behavior for internal failures) is appropriate.
	aadC2S := crypto.BuildAAD(endpoint, salt, "c2s", "session", method)
	c2sEnc, c2sCounter, err := sk.Encryptor("c2s", "session", method)
	if err != nil {
		log.Error("[SERVER] c2s encryptor", "err", err)
		serveReject(w, http.StatusInternalServerError)
		return
	}

	aadS2C := crypto.BuildAAD(endpoint, salt, "s2c", "session", method)
	s2cEnc, s2cCounter, err := sk.Encryptor("s2c", "session", method)
	if err != nil {
		log.Error("[SERVER] s2c encryptor", "err", err)
		serveReject(w, http.StatusInternalServerError)
		return
	}

	rc := http.NewResponseController(w)
	_ = rc.EnableFullDuplex()

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)

	_ = rc.Flush()

	c2sReader := crypto.NewDecryptedReader(r.Body, aadC2S, c2sEnc, c2sCounter)
	c2sReader.SetLeftoverFrames(first.Leftover)

	s2cWriter := crypto.NewRecordWriter(w, s2cEnc, s2cCounter, aadS2C)
	s2cCfg := shaper.Config{BatchWindowMS: h.batchWindowMS, Cover: shaper.CoverConfig{BudgetRatio: h.coverBudgetRatio, BudgetCap: h.coverBudgetCap}}
	if endpoint == sharedconfig.EndpointUDP {
		// UDP uses a short 1ms batch window so datagram bursts are merged
		// into single encrypted records instead of one record + forced
		// HTTP/2 flush per datagram.
		s2cCfg.BatchWindowMS = 1
	}
	s2cShaper := shaper.New(s2cWriter, s2cCfg)
	defer s2cShaper.Close() //nolint:errcheck

	var handleErr error
	switch endpoint {
	case sharedconfig.EndpointTCP:
		stats.RecordServerTCPStream()
		// cancelRead unblocks the relay's client-read goroutine immediately
		// when the relay terminates (idle timeout/error), instead of letting
		// it linger on the request body until net/http closes it.
		handleErr = h.tcpHandler.Handle(r.Context(), c2sReader, s2cShaper, target, func() { _ = r.Body.Close() })
	case sharedconfig.EndpointUDP:
		stats.RecordServerUDPStream()
		handleErr = h.udpHandler.Handle(r.Context(), c2sReader, s2cShaper, target)
	case sharedconfig.EndpointICMP:
		stats.RecordServerICMPStream()
		handleErr = h.icmpHandler.Handle(c2sReader, s2cShaper, target)
	}
	if handleErr != nil {
		log.Info("[SERVER] handler finished with error", "target", target, "endpoint", endpoint, "err", handleErr)
	} else {
		log.Debug("[SERVER] handler finished", "target", target, "endpoint", endpoint)
	}
}
