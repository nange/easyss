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
			resetTimer(timer, idleTimeout)
		case <-activity:
			resetTimer(timer, idleTimeout)
		case <-timer.C:
			if onClose != nil {
				onClose()
			}
			// Drain both goroutine results so they can exit cleanly.
			for i := 0; i < 2; i++ {
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
