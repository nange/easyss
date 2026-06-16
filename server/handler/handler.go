package handler

import (
	"encoding/base64"
	"net/http"
	"strings"
	"time"

	"github.com/nange/easyss/v3/crypto"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/protocol"
	"github.com/nange/easyss/v3/server/nextproxy"
	"github.com/nange/easyss/v3/shaper"
)

type ProxyHandler struct {
	masterKey        []byte
	allowedMethods   map[protocol.Method]bool
	handshakeTimeout time.Duration
	nextProxy        *nextproxy.NextProxy
	tcpHandler       *TCPHandler
	udpHandler       *UDPHandler
	icmpHandler      *ICMPHandler
}

type ProxyHandlerConfig struct {
	MasterKey         []byte
	AllowedMethods    []string
	HandshakeTimeout  time.Duration
	StreamIdleTimeout time.Duration
	UDPIdleTimeout    time.Duration
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

	return &ProxyHandler{
		masterKey:        cfg.MasterKey,
		allowedMethods:   allowed,
		handshakeTimeout: cfg.HandshakeTimeout,
		nextProxy:        cfg.NextProxy,
		tcpHandler:       NewTCPHandler(cfg.StreamIdleTimeout, cfg.NextProxy),
		udpHandler:       NewUDPHandler(cfg.UDPIdleTimeout, cfg.NextProxy),
		icmpHandler:      NewICMPHandler(),
	}
}

func (h *ProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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

	endpoint := r.URL.Path
	sk, err := crypto.NewStreamKeys(h.masterKey, salt, endpoint)
	if err != nil {
		ServeFallback(w, r)
		return
	}

	first, err := sk.ReadFirstRecordWithTimeout(r.Context(), r.Body, h.handshakeTimeout)
	if err != nil {
		log.Error("[SERVER] read first record", "remote", r.RemoteAddr, "endpoint", endpoint, "err", err)
		ServeFallback(w, r)
		return
	}

	if !first.Handshake.MatchesEndpoint(endpoint) {
		log.Error("[SERVER] endpoint mismatch", "remote", r.RemoteAddr, "proto", first.Handshake.Proto.String(), "endpoint", endpoint)
		ServeFallback(w, r)
		return
	}

	if !h.allowedMethods[first.Handshake.Method] {
		log.Error("[SERVER] method not allowed", "remote", r.RemoteAddr, "method", first.Handshake.Method.String())
		ServeFallback(w, r)
		return
	}

	log.Info("[SERVER] proxy", "target", first.Handshake.Target, "remote", r.RemoteAddr)

	rc := http.NewResponseController(w)
	_ = rc.EnableFullDuplex()

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)

	_ = rc.Flush()

	target := first.Handshake.Target
	method := first.Handshake.Method

	aadC2S := crypto.BuildAAD(endpoint, salt, "c2s", "session", method)
	c2sEnc, c2sCounter, err := sk.Encryptor("c2s", "session", method)
	if err != nil {
		return
	}
	c2sReader := crypto.NewDecryptedReader(r.Body, aadC2S, c2sEnc, c2sCounter)
	c2sReader.SetLeftoverFrames(first.Leftover)

	aadS2C := crypto.BuildAAD(endpoint, salt, "s2c", "session", method)
	s2cEnc, s2cCounter, err := sk.Encryptor("s2c", "session", method)
	if err != nil {
		return
	}
	s2cWriter := crypto.NewRecordWriter(w, s2cEnc, s2cCounter, aadS2C)
	s2cShaper := shaper.NewLight(s2cWriter, shaper.Config{Mode: "light", BatchWindowMS: 5, Cover: shaper.CoverConfig{}})
	defer s2cShaper.Close() //nolint:errcheck

	var handleErr error
	switch {
	case strings.HasSuffix(endpoint, "/tcp"):
		handleErr = h.tcpHandler.Handle(c2sReader, s2cShaper, target)
	case strings.HasSuffix(endpoint, "/udp"):
		handleErr = h.udpHandler.Handle(c2sReader, s2cShaper, target)
	case strings.HasSuffix(endpoint, "/icmp"):
		handleErr = h.icmpHandler.Handle(c2sReader, s2cShaper, target)
	}
	if handleErr != nil {
		log.Debug("[SERVER] handler finished with error", "target", target, "endpoint", endpoint, "err", handleErr)
	} else {
		log.Debug("[SERVER] handler finished", "target", target, "endpoint", endpoint)
	}
}
