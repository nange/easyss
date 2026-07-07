package shaper

import (
	cryptorand "crypto/rand"
	"sync"
	"time"

	"github.com/nange/easyss/v3/protocol"
	"github.com/nange/easyss/v3/util/bytespool"
)

type coverInjector struct {
	cfg       CoverConfig
	mu        sync.Mutex
	budget    float64
	timer     *time.Timer
	inject    func(f protocol.Frame) error
	isClosing func() bool
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

	ci := &coverInjector{
		cfg:       cfg,
		inject:    inject,
		isClosing: isClosing,
	}
	ci.timer = time.AfterFunc(time.Duration(cfg.IdleTimeout)*time.Millisecond, ci.onIdle)
	ci.timer.Stop()
	return ci
}

func (ci *coverInjector) addBudget(realBytes int) {
	ci.mu.Lock()
	defer ci.mu.Unlock()
	ci.budget += float64(realBytes) * ci.cfg.BudgetRatio
	ci.timer.Reset(ci.jitterTimeout())
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
	if budget < float64(ci.cfg.MinSize) {
		ci.mu.Unlock()
		return
	}

	maxFrameSize := min(ci.cfg.MaxSize, int(budget))
	frameSize := ci.randomSize(maxFrameSize)
	ci.budget -= float64(frameSize)

	if ci.budget >= float64(ci.cfg.MinSize) {
		ci.timer.Reset(ci.jitterTimeout())
	}

	frame := ci.generateFrame(frameSize)
	ci.mu.Unlock()

	_ = ci.inject(frame)
}

func (ci *coverInjector) randomSize(maxFrameSize int) int {
	minSize := ci.cfg.MinSize
	if minSize >= maxFrameSize {
		return maxFrameSize
	}
	return minSize + randomInt(maxFrameSize-minSize)
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
