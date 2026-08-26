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

// resetRotation clears the connection-scoped state of a slot whose
// connection no longer exists (closed by shrink/retire/rotation, or never
// established): the deadline, bytes carried and the expiring/degraded marks
// all go back to the "no connection" baseline. expireAt is zeroed rather
// than set to a fresh deadline — rotationDue only triggers on expireAt > 0,
// so a slot without a connection is never judged overdue. The next dial
// calls resetConn, which sets the real deadline. grow calls this when it
// re-activates a pre-allocated slot, so a revived slot cannot inherit the
// previous connection's expired deadline or verdicts.
func (s *transportSlot) resetRotation() {
	s.expireAt.Store(0)
	s.connBytes.Store(0)
	s.expiring.Store(false)
	s.degraded.Store(false)
}

// resetConn (re)initializes the rotation state for a freshly established
// connection: the lifetime deadline (with per-connection jitter), the bytes
// carried and the expiring mark all start fresh. The degraded mark is
// cleared too: degradation is a verdict about the previous connection's
// throughput, and a freshly dialed connection deserves a clean slate until
// the sampler or a probe re-evaluates it — in particular a slot retired
// while degraded and later re-activated by grow reuses this same
// transportSlot object, and its new connection must not inherit the old
// verdict.
func (s *transportSlot) resetConn(connLifetime time.Duration) {
	s.resetRotation()
	s.expireAt.Store(time.Now().Add(rotationLifetime(connLifetime)).UnixNano())
}
