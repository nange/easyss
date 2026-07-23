package stats

import (
	"sync"
	"time"
)

var (
	speedOnce sync.Once
	speedDone chan struct{}
)

// StartSpeedMonitor starts a background goroutine that periodically samples
// raw byte counters and computes upload/download speed via EWMA.
func StartSpeedMonitor() {
	speedOnce.Do(func() {
		speedDone = make(chan struct{})
		go g.speedLoop()
	})
}

// StopSpeedMonitor stops the background speed monitoring goroutine.
func StopSpeedMonitor() {
	select {
	case <-speedDone:
		// Already stopped.
	default:
		close(speedDone)
	}
}

func (s *stats) speedLoop() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	var lastSent, lastRecv int64
	const alpha = 0.5

	for {
		select {
		case <-ticker.C:
			curSent := s.rawBytesSent.Load()
			curRecv := s.rawBytesRecv.Load()

			deltaSent := curSent - lastSent
			deltaRecv := curRecv - lastRecv
			lastSent, lastRecv = curSent, curRecv

			// Clamp negative deltas (counter reset, should not happen with monotonic counters).
			if deltaSent < 0 {
				deltaSent = 0
			}
			if deltaRecv < 0 {
				deltaRecv = 0
			}

			// EWMA update.
			oldUp := s.uploadSpeed.Load()
			oldDown := s.downloadSpeed.Load()
			newUp := int64(float64(deltaSent)*alpha + float64(oldUp)*(1-alpha))
			newDown := int64(float64(deltaRecv)*alpha + float64(oldDown)*(1-alpha))
			s.uploadSpeed.Store(newUp)
			s.downloadSpeed.Store(newDown)

			// Track peak speeds.
			for {
				peak := s.peakUploadSpeed.Load()
				if newUp <= peak {
					break
				}
				if s.peakUploadSpeed.CompareAndSwap(peak, newUp) {
					break
				}
			}
			for {
				peak := s.peakDownloadSpeed.Load()
				if newDown <= peak {
					break
				}
				if s.peakDownloadSpeed.CompareAndSwap(peak, newDown) {
					break
				}
			}
		case <-speedDone:
			return
		}
	}
}
