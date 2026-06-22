package client

import (
	"sync"
	"time"
)

// LatencyTracker maintains an EWMA-smoothed round-trip time estimate
// derived from normal proxy traffic.
type LatencyTracker struct {
	mu       sync.Mutex
	estimate time.Duration
	count    int64
	offset   time.Duration
}

// NewLatencyTracker creates a tracker with the given display offset.
// offset is subtracted from the EWMA estimate before reporting, to account
// for the server→target connection setup time that is not proxy latency.
func NewLatencyTracker(offset time.Duration) *LatencyTracker {
	return &LatencyTracker{offset: offset}
}

// Record feeds a new raw RTT sample into the EWMA.
func (t *LatencyTracker) Record(rtt time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()

	const alpha = 0.3
	if t.count == 0 {
		t.estimate = rtt
	} else {
		t.estimate = time.Duration(float64(rtt)*alpha + float64(t.estimate)*(1-alpha))
	}
	t.count++
}

// Estimate returns the current estimate minus the configured offset.
// The returned bool is false when no measurement has been recorded yet.
// The result is never negative.
func (t *LatencyTracker) Estimate() (time.Duration, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.count == 0 {
		return 0, false
	}

	adjusted := t.estimate - t.offset
	if adjusted < 0 {
		adjusted = 0
	}
	return adjusted, true
}
