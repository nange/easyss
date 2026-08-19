package http2

import (
	"net/http"
	"sync/atomic"
	"time"
)

// transportSlot hosts one HTTP/2 connection (a stdlib http.Transport pinned
// to a single connection via MaxConnsPerHost=1) plus the state that the
// scheduler and the connection lifecycle act on.
type transportSlot struct {
	// idx is the slot's stable index in the scheduler's pre-allocated
	// array, set once at construction. Retire swap-removes slots, so the
	// live position and idx diverge; idx is used for stats reporting.
	idx int

	t      *http.Transport
	active atomic.Int32
	heavy  atomic.Int32 // number of active heavy streams (>= HeavyStreamThreshold bytes)
	// bytesRecv is the cumulative downloaded bytes across streams on this
	// slot; sampled by the health loop to estimate recent throughput.
	bytesRecv atomic.Int64
	// degraded marks a slot whose download throughput stays below the
	// degraded threshold while hosting heavy streams; new streams avoid it
	// and its idle connection is retired early.
	degraded atomic.Bool

	// Connection rotation state.
	expireAt  atomic.Int64 // unix nano deadline of the current connection (dial time + lifetime + jitter)
	connBytes atomic.Int64 // bytes carried over the current connection in either direction
	// expiring marks a slot whose connection exceeded the lifetime or bytes
	// limit; new streams avoid it and its idle connection is closed so the
	// next stream dials a fresh one. Cleared when a new connection is
	// established or the rotation completes.
	expiring atomic.Bool

	// Health-loop state, touched only from the health loop goroutine.
	lastBytes     int64
	lastHeavy     int // last observed heavy count, tracks heavy 0->1 transitions
	lowCycles     int
	recoverCycles int

	// Probe state, touched only from the health loop goroutine. suspected
	// marks a slot whose passive throughput stayed low long enough to
	// deserve an active probe confirmation; probeLowCycles counts
	// consecutive slow probes; lastProbeAt enforces the probe cooldown.
	suspected      bool
	probeLowCycles int
	lastProbeAt    time.Time
}

// eligible reports whether the slot may host a new stream under the given
// skip filters. The scheduler queries it instead of reading the flags
// directly, so the meaning of "healthy" lives with the slot.
func (s *transportSlot) eligible(skipHeavy, skipDegraded, skipExpiring bool) bool {
	if skipHeavy && s.heavy.Load() > 0 {
		return false
	}
	if skipDegraded && s.degraded.Load() {
		return false
	}
	if skipExpiring && s.expiring.Load() {
		return false
	}
	return true
}

// resetConn (re)initializes the rotation state for a freshly established
// connection: the lifetime deadline (with per-connection jitter), the bytes
// carried and the expiring mark all start fresh.
func (s *transportSlot) resetConn(connLifetime time.Duration) {
	s.expireAt.Store(time.Now().Add(rotationLifetime(connLifetime)).UnixNano())
	s.connBytes.Store(0)
	s.expiring.Store(false)
}
