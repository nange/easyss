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
	d := max(base/3, 3*time.Second)
	if d > 15*time.Second {
		d = 15 * time.Second
	}
	return d
}
