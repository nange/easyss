package handler

import (
	"net"
	"net/http"
	"time"

	sharedconfig "github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/protocol"
	"github.com/nange/easyss/v3/server/nextproxy"
	"github.com/nange/easyss/v3/shaper"
)

// ProxyHandler owns the three per-protocol session handlers but no next-proxy
// state of its own: each handler holds the proxy it routes through, so routing
// has a single owner and cannot drift between them.
type ProxyHandler struct {
	masterKey        []byte
	allowedMethods   map[protocol.Method]bool
	handshakeTimeout time.Duration
	shaperCfg        shaper.Config
	tcp              *tcpHandler
	udp              *udpHandler
	icmp             *icmpHandler
	saltCache        *saltCache
	ipLimiter        *ipRateLimiter
}

type ProxyHandlerConfig struct {
	MasterKey      []byte
	AllowedMethods []string
	// Timeouts carries every derived duration (see config.NewTimeouts), and
	// Shaper the shaper settings (normalized here). Both are built by the
	// caller from the server config, so this struct no longer re-derives or
	// re-clamps anything.
	Timeouts  sharedconfig.Timeouts
	Shaper    shaper.Config
	NextProxy *nextproxy.NextProxy
	// HandshakeTimeout overrides the bootstrap-record wait. 0 uses
	// Timeouts.Base, which is what the server passes; tests shrink it without
	// touching the derived idle timeouts.
	HandshakeTimeout time.Duration
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

	shaperCfg := cfg.Shaper.Normalize()

	// Bound the bootstrap-record wait. A handshake request occupies two
	// goroutines (the handler plus the first-record reader) for the whole
	// wait, and any request with a well-formed x-es header — no password
	// required — can hold them, so an over-generous timeout is a cheap DoS
	// amplification channel. Legit clients write their bootstrap record
	// immediately after opening the stream, so even high-RTT links finish
	// far below this cap.
	handshakeTimeout := cfg.HandshakeTimeout
	if handshakeTimeout <= 0 {
		handshakeTimeout = cfg.Timeouts.Base
	}
	if handshakeTimeout <= 0 {
		handshakeTimeout = maxHandshakeTimeout
	}
	if handshakeTimeout > maxHandshakeTimeout {
		handshakeTimeout = maxHandshakeTimeout
	}

	return &ProxyHandler{
		masterKey:        cfg.MasterKey,
		allowedMethods:   allowed,
		handshakeTimeout: handshakeTimeout,
		shaperCfg:        shaperCfg,
		tcp:              newTCPHandler(cfg.Timeouts.StreamIdle, cfg.Timeouts.Base, cfg.NextProxy),
		udp:              newUDPHandler(cfg.Timeouts.UDPIdle, cfg.Timeouts.Base, cfg.NextProxy),
		icmp:             newICMPHandler(cfg.Timeouts.Base),
		saltCache:        newSaltCache(),
		ipLimiter:        newIPRateLimiter(),
	}
}

// maxHandshakeTimeout caps how long the server waits for a stream's first
// encrypted record before answering 408 (see NewProxyHandler).
const maxHandshakeTimeout = 8 * time.Second

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// remoteString returns a printable remote endpoint for logging. It is nil safe
// on purpose: a dialed connection may report an unset (nil) RemoteAddr, and a
// bare RemoteAddr().String() would panic. The next-proxy path does not use it
// (a SOCKS5 connection reports the proxy's address, so dialTarget logs the
// configured proxy instead).
func remoteString(conn net.Conn) string {
	if conn == nil {
		return ""
	}
	if ra := conn.RemoteAddr(); ra != nil {
		return ra.String()
	}
	return ""
}
