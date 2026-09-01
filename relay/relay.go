package relay

import (
	"errors"
	"fmt"
	"io"
	"time"
)

func resetTimer(t *time.Timer, d time.Duration) {
	if !t.Stop() {
		select {
		case <-t.C:
		default:
		}
	}
	t.Reset(d)
}

type Result struct {
	Err      error
	IdleMsg  string
	TimedOut bool
	// Drained reports that the relay was terminated early by the drain
	// mechanism (BidirectionalWithDrain): the stream sat idle beyond
	// drainIdle while drainWhen reported the owning slot is due for
	// eviction, so the lingering connection was closed before the full idle
	// timeout.
	Drained bool
}

// Bidirectional runs two copy goroutines concurrently with a shared idle
// timeout. The signalActivity callback passed to each copy function should be
// invoked whenever data flows, to reset the idle timer. If no activity is
// observed for idleTimeout, onClose is invoked and a timeout error is returned.
//
// The onClose callback is invoked exactly once when the relay terminates
// (whether by completion, error, or timeout).
//
// Each copy function returns nil on clean EOF, or an error otherwise. The
// first non-nil, non-EOF error is returned. If both copies complete without
// error, nil is returned.
func Bidirectional(idleTimeout time.Duration, onClose func(), srcToDst, dstToSrc func(signalActivity func()) error) Result {
	return bidirectional(idleTimeout, nil, 0, onClose, srcToDst, dstToSrc)
}

// BidirectionalWithDrain is Bidirectional plus an early-close drain
// mechanism: while drainWhen reports the relay should wind down (e.g. the
// owning connection slot is due for rotation or retirement), a relay that has
// been idle for at least drainIdle is closed instead of waiting out the full
// idle timeout. Activity (signalActivity or a completed copy) restarts the
// idle clock, so streams that keep flowing are never drained — only
// lingering idle connections, which is exactly what postpones slot rotation.
// drainWhen == nil or drainIdle <= 0 disables the mechanism and the behavior
// is identical to Bidirectional.
func BidirectionalWithDrain(idleTimeout time.Duration, drainWhen func() bool, drainIdle time.Duration, onClose func(), srcToDst, dstToSrc func(signalActivity func()) error) Result {
	return bidirectional(idleTimeout, drainWhen, drainIdle, onClose, srcToDst, dstToSrc)
}

func bidirectional(idleTimeout time.Duration, drainWhen func() bool, drainIdle time.Duration, onClose func(), srcToDst, dstToSrc func(signalActivity func()) error) Result {
	activity := make(chan struct{}, 1)
	signalActivity := func() {
		select {
		case activity <- struct{}{}:
		default:
		}
	}

	errCh := make(chan error, 2)
	go func() { errCh <- srcToDst(signalActivity) }()
	go func() { errCh <- dstToSrc(signalActivity) }()

	timer := time.NewTimer(idleTimeout)
	defer timer.Stop()

	// idleSince tracks the moment the relay's idle clock started, kept in
	// lockstep with the timer: both restart on activity and on a completed
	// copy. The drain check compares against it so the drain grace is
	// measured from the same reference as the idle timeout.
	idleSince := time.Now()
	resetIdle := func() {
		idleSince = time.Now()
		resetTimer(timer, idleTimeout)
	}

	// Drain ticker: sampled periodically rather than re-armed on every
	// state change, because the slot marks (drainWhen) flip asynchronously
	// from the health loop. The tick is a fraction of drainIdle so the
	// drain fires within ~drainIdle..drainIdle+tick of going idle.
	var drainC <-chan time.Time
	if drainWhen != nil && drainIdle > 0 {
		tick := max(drainIdle/6, 10*time.Millisecond)
		drainTicker := time.NewTicker(tick)
		defer drainTicker.Stop()
		drainC = drainTicker.C
	}

	done := 0
	var firstErr error
	for done < 2 {
		select {
		case err := <-errCh:
			done++
			if err != nil && !errors.Is(err, io.EOF) && firstErr == nil {
				firstErr = err
			}
			if firstErr != nil || done == 2 {
				if onClose != nil {
					onClose()
				}
				return Result{Err: firstErr}
			}
			resetIdle()
		case <-activity:
			resetIdle()
		case <-drainC:
			if drainWhen() && time.Since(idleSince) >= drainIdle {
				if onClose != nil {
					onClose()
				}
				// Drain both goroutine results so they can exit cleanly.
				for range 2 {
					select {
					case <-errCh:
					default:
					}
				}
				return Result{
					Err:      fmt.Errorf("stream drained: idle for %v while the slot is due for eviction", drainIdle),
					IdleMsg:  fmt.Sprintf("drained after %v idle (slot due for eviction)", drainIdle),
					TimedOut: true,
					Drained:  true,
				}
			}
		case <-timer.C:
			if onClose != nil {
				onClose()
			}
			// Drain both goroutine results so they can exit cleanly.
			for range 2 {
				select {
				case <-errCh:
				default:
				}
			}
			return Result{
				Err:      fmt.Errorf("relay idle timeout after %v", idleTimeout),
				IdleMsg:  fmt.Sprintf("idle timeout after %v", idleTimeout),
				TimedOut: true,
			}
		}
	}
	// Unreachable in practice: the loop only exits when done == 2, and every
	// path that increments done to 2 returns from inside the select. This
	// return exists solely to satisfy the compiler's control-flow analysis.
	return Result{Err: firstErr}
}
