package shaper

import (
	cryptorand "crypto/rand"
	"sync"
	"time"

	"github.com/nange/easyss/v3/protocol"
	"github.com/nange/easyss/v3/util/bytespool"
)

type coverInjector struct {
	cfg              CoverConfig
	mu               sync.Mutex
	budget           float64
	timer            *time.Timer
	inject           func(f protocol.Frame) error
	isClosing        func() bool
	lastReset        time.Time
	minResetInterval time.Duration
	totalSent        int64
}

func newCoverInjector(cfg CoverConfig, inject func(protocol.Frame) error, isClosing func() bool) *coverInjector {
	if cfg.BudgetRatio == 0 {
		return nil
	}
	if cfg.BudgetRatio < 0 || cfg.BudgetRatio > 1 {
		cfg.BudgetRatio = 0.10
	}
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = 100
	}
	if cfg.MinSize <= 0 {
		cfg.MinSize = 64
	}
	if cfg.MaxSize <= 0 {
		cfg.MaxSize = 1500
	}
	if cfg.MaxSize < cfg.MinSize {
		cfg.MaxSize = cfg.MinSize
	}
	if cfg.BudgetCap <= 0 {
		cfg.BudgetCap = 512 * 1024
	}

	ci := &coverInjector{
		cfg:              cfg,
		inject:           inject,
		isClosing:        isClosing,
		minResetInterval: time.Duration(cfg.IdleTimeout) * time.Millisecond / 2,
	}
	ci.timer = time.AfterFunc(time.Duration(cfg.IdleTimeout)*time.Millisecond, ci.onIdle)
	ci.timer.Stop()
	return ci
}

func (ci *coverInjector) addBudget(realBytes int) {
	ci.mu.Lock()
	ci.totalSent += int64(realBytes)
	ci.budget += float64(realBytes) * ci.cfg.BudgetRatio
	if ci.budget > float64(ci.cfg.BudgetCap) {
		ci.budget = float64(ci.cfg.BudgetCap)
	}
	// Debounce timer resets to avoid excessive operations on the hot path.
	// The timer only needs to be reset often enough that onIdle fires within
	// ~IdleTimeout after the last frame, not after every single frame.
	now := time.Now()
	if now.Sub(ci.lastReset) >= ci.minResetInterval {
		ci.timer.Reset(ci.jitterTimeout())
		ci.lastReset = now
	}
	ci.mu.Unlock()
}

func (ci *coverInjector) stop() {
	ci.mu.Lock()
	defer ci.mu.Unlock()
	ci.timer.Stop()
	ci.budget = 0
}

func (ci *coverInjector) onIdle() {
	ci.mu.Lock()

	if ci.isClosing() {
		ci.mu.Unlock()
		return
	}

	budget := ci.budget
	// Use smooth dynamic frame size: linearly scales with totalSent from
	// [64, 1500] at 0 bytes to [4096, 8192] at 1MB and beyond.
	// This avoids a detectable step at any threshold.
	minSize, maxSize := ci.coverFrameSizeRange()

	if budget < float64(minSize) {
		ci.mu.Unlock()
		return
	}

	maxFrameSize := min(maxSize, int(budget))
	frameSize := minSize + randomInt(maxFrameSize-minSize+1)
	ci.budget -= float64(frameSize)

	if ci.budget >= float64(minSize) {
		ci.timer.Reset(ci.jitterTimeout())
	}

	frame := ci.generateFrame(frameSize)
	ci.mu.Unlock()

	_ = ci.inject(frame)
}

func (ci *coverInjector) coverFrameSizeRange() (minSize, maxSize int) {
	const smoothSpan = 1 << 20 // 1MB
	ratio := float64(min(ci.totalSent, smoothSpan)) / float64(smoothSpan)
	minSize = 64 + int(ratio*(4096-64))
	maxSize = 1500 + int(ratio*(8192-1500))
	return
}

func (ci *coverInjector) generateFrame(size int) protocol.Frame {
	payload := bytespool.Get(size)[:size]
	_, _ = cryptorand.Read(payload)
	return protocol.Frame{
		Type:    protocol.FrameCOVER,
		Length:  uint16(size),
		Payload: payload,
	}
}

func (ci *coverInjector) jitterTimeout() time.Duration {
	minMS := ci.cfg.IdleTimeout * 60 / 100
	maxMS := ci.cfg.IdleTimeout
	if minMS >= maxMS {
		minMS = maxMS
	}
	ms := minMS + randomInt(maxMS-minMS)
	return time.Duration(ms) * time.Millisecond
}
