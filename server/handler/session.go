package handler

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/nange/easyss/v3/crypto"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/protocol"
	"github.com/nange/easyss/v3/server/nextproxy"
	"github.com/nange/easyss/v3/shaper"
	"github.com/nange/easyss/v3/util"
)

// sendRST pushes an RST frame through the s2c shaper and flushes it: the
// uniform way every handler tells the client that its stream failed after
// the response was committed.
func sendRST(s2c shaper.Shaper) {
	_ = s2c.PushFrame(protocol.NewFrameRST())
	_ = s2c.Flush()
}

// nextClientFrame reads the next actionable frame from the client stream,
// skipping PADDING/COVER. done reports that the stream ended (FIN or RST);
// the returned frame is then the terminal one. err aborts everything.
func nextClientFrame(dr *crypto.DecryptedReader) (frame protocol.Frame, done bool, err error) {
	for {
		f, err := dr.ReadFrame()
		if err != nil {
			return protocol.Frame{}, false, err
		}
		switch f.Type {
		case protocol.FrameFIN, protocol.FrameRST:
			return f, true, nil
		case protocol.FramePADDING, protocol.FrameCOVER:
			continue
		default:
			return f, false, nil
		}
	}
}

// lanHostOf extracts the host part of a remote address in either
// "host:port" (TCPAddr/UDPAddr) or bare-IP form (IPConn). An IPConn's
// RemoteAddr is a *net.IPAddr whose String() carries no port — with or
// without a %zone suffix for link-local IPv6 — so net.SplitHostPort
// alone would always fail for it and the SSRF check would never fire.
func lanHostOf(addr string) string {
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	if i := strings.LastIndexByte(addr, '%'); i >= 0 {
		return addr[:i]
	}
	return addr
}

// rejectLANConn closes conn when its remote address is a LAN/private IP and
// returns the rejection error. It is the post-dial SSRF guard shared by the
// TCP/UDP/ICMP handlers: the handshake validated the target, but the dial
// re-resolves domain targets, so a DNS-rebinding name could resolve to a LAN
// host here. Reject the connection before anything is sent.
func rejectLANConn(conn net.Conn) error {
	if ra := conn.RemoteAddr(); ra != nil {
		if host := lanHostOf(ra.String()); util.IsLANIP(host) {
			_ = conn.Close()
			return fmt.Errorf("ssrf: rejected lan destination %s", host)
		}
	}
	return nil
}

// dialer is the shared outbound-dial piece of the TCP/UDP/ICMP handlers:
// next-proxy routing (with its SSRF pre-check) and the direct dial with the
// post-dial SSRF guard.
type dialer struct {
	nextProxy *nextproxy.NextProxy
	// useProxy decides whether target goes through the next proxy. nil means
	// the next-proxy branch is unreachable (ICMP: raw sockets cannot be
	// carried by a SOCKS5 proxy, and the handler carries no context).
	useProxy func(target string) bool
	// dial opens the direct outbound connection for target.
	dial func(ctx context.Context, network, target string) (net.Conn, error)
}

// dialTarget opens the outbound connection and returns it together with a
// printable remote address for logging. The remote is resolved here because
// the next-proxy path yields a SOCKS5 connection whose RemoteAddr() is nil.
func (d *dialer) dialTarget(ctx context.Context, network, target string) (net.Conn, string, error) {
	if d.nextProxy != nil && d.useProxy != nil && d.useProxy(target) {
		// Re-run the SSRF check at dial time: the handshake-time check may
		// be long past, and a DNS-rebinding name can resolve differently
		// now. The post-dial check below cannot run on this path — the
		// SOCKS5 connection reports the proxy's address, not the target's —
		// so the proxy's own resolver remains a (trusted, admin-configured)
		// residual risk.
		if util.IsLANHostResolved(ctx, target) {
			return nil, "", fmt.Errorf("ssrf: rejected lan destination %s", target)
		}
		log.Info("[HANDLE] dialing via next proxy", "target", target, "proxy", d.nextProxy.Host())
		conn, err := d.nextProxy.DialContext(ctx, network, target)
		if err != nil {
			return nil, "", err
		}
		return conn, d.nextProxy.Host(), nil
	}
	conn, err := d.dial(ctx, network, target)
	if err != nil {
		return nil, "", err
	}
	if err := rejectLANConn(conn); err != nil {
		return nil, "", err
	}
	return conn, remoteString(conn), nil
}
