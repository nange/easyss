package config

import "time"

// Timeout derivation helpers: the single source of truth for how the
// user-configured base timeout maps to each idle/dial timeout. The client
// (runner.Run) and the server (server.New) both derive their timeouts
// through these functions, so a change to any formula takes effect on both
// sides and in the tests that mirror the derivation.
//
// The base timeout is passed in as an argument: these functions never read
// the configuration themselves, callers hand over their own configured
// value (default 30s, see DefaultTimeout).

// StreamIdleTimeout returns the TCP stream idle timeout derived from the
// user-configured base timeout (4 x base; default 30s -> 120s). The
// multiplier bounds how long a stream may sit completely silent before the
// relay tears it down: generous enough to survive slow, idle connections
// (SSH, long-polling) while still reaping half-open or dead peers.
func StreamIdleTimeout(base time.Duration) time.Duration {
	return 4 * base
}

// UDPIdleTimeout returns the UDP session idle/read timeout (2 x base;
// default 30s -> 60s).
func UDPIdleTimeout(base time.Duration) time.Duration {
	return 2 * base
}

// DialTimeout returns the outbound dial timeout: base / 3, clamped to
// [3s, 15s]. Shared by the client (direct dials) and the server (TCP
// handler dials) so both sides always derive the same value.
func DialTimeout(base time.Duration) time.Duration {
	d := min(max(base/3, 3*time.Second), 15*time.Second)
	return d
}

// Timeouts is the complete derived timeout set a core needs. Callers build it
// once from the configured base timeout and pass it down, instead of each
// layer recomputing (or worse, hand-rolling) one of the values — the client
// used to pass timeout/3 as the DNS response timeout while the server derived
// its dial timeout through DialTimeout.
type Timeouts struct {
	Base       time.Duration // user-configured base timeout
	Dial       time.Duration // outbound dial (base/3, clamped to [3s,15s])
	StreamIdle time.Duration // TCP stream idle (4 x base)
	UDPIdle    time.Duration // UDP session idle (2 x base)
	DNSResp    time.Duration // DNS response read-idle (base/3, unclamped)
}

// NewTimeouts derives the whole set from the user-configured base timeout
// (the default is applied when base <= 0).
func NewTimeouts(base time.Duration) Timeouts {
	if base <= 0 {
		base = time.Duration(DefaultTimeout) * time.Second
	}
	return Timeouts{
		Base:       base,
		Dial:       DialTimeout(base),
		StreamIdle: StreamIdleTimeout(base),
		UDPIdle:    UDPIdleTimeout(base),
		DNSResp:    base / 3,
	}
}
