package stats

import (
	"sync"
	"time"
)

var (
	speedMu      sync.Mutex
	speedRunning bool
	speedDone    chan struct{}
)

// StartSpeedMonitor 启动一个后台 goroutine，周期性采样原始字节计数器，
// 并通过 EWMA 计算上传/下载速度。
func StartSpeedMonitor() {
	speedMu.Lock()
	defer speedMu.Unlock()
	if speedRunning {
		return
	}
	speedRunning = true
	speedDone = make(chan struct{})
	go g.speedLoop(speedDone)
}

// StopSpeedMonitor 停止后台速度监控 goroutine。
func StopSpeedMonitor() {
	speedMu.Lock()
	defer speedMu.Unlock()
	if !speedRunning {
		return
	}
	speedRunning = false
	close(speedDone)
}

// speedLoop 采样原始字节计数器，直到 done 关闭。停止通道通过参数传入
// 而不是读取包级全局变量：否则经过一次 Start/Stop/Start 循环后，旧的
// goroutine 会观察到新通道而永不退出，导致两个监控器更新同一组仪表。
func (s *stats) speedLoop(done <-chan struct{}) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	var lastSent, lastRecv int64
	lastSent = s.rawBytesSent.Load()
	lastRecv = s.rawBytesRecv.Load()
	const alpha = 0.5

	for {
		select {
		case <-ticker.C:
			curSent := s.rawBytesSent.Load()
			curRecv := s.rawBytesRecv.Load()

			deltaSent := curSent - lastSent
			deltaRecv := curRecv - lastRecv
			lastSent, lastRecv = curSent, curRecv

			// 钳制负增量（计数器重置，单调计数器下不应发生）。
			if deltaSent < 0 {
				deltaSent = 0
			}
			if deltaRecv < 0 {
				deltaRecv = 0
			}

			// EWMA 更新。
			oldUp := s.uploadSpeed.Load()
			oldDown := s.downloadSpeed.Load()
			newUp := int64(float64(deltaSent)*alpha + float64(oldUp)*(1-alpha))
			newDown := int64(float64(deltaRecv)*alpha + float64(oldDown)*(1-alpha))
			s.uploadSpeed.Store(newUp)
			s.downloadSpeed.Store(newDown)

			// 记录峰值速度。
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
		case <-done:
			return
		}
	}
}
