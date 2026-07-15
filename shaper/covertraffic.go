package shaper

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/nange/easyss/v3/protocol"
	"github.com/nange/easyss/v3/util/bytespool"
)

var coverRNG = newSeededChaCha8()

type coverInjector struct {
	cfg              CoverConfig
	mu               sync.Mutex
	budget           float64
	timer            *time.Timer
	inject           func(f protocol.Frame) error
	isClosing        func() bool
	lastReset        time.Time
	lastRealData     atomic.Int64
	minResetInterval time.Duration
	totalSent        atomic.Int64
	coverThreshold   int64
	stopped          atomic.Bool
}

func newCoverInjector(cfg CoverConfig, inject func(protocol.Frame) error, isClosing func() bool) *coverInjector {
	if cfg.BudgetRatio == 0 {
		return nil
	}
	if cfg.BudgetRatio < 0 || cfg.BudgetRatio > 1 {
		cfg.BudgetRatio = 0.10
	}
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = 300
	}
	if cfg.MinSize <= 0 {
		cfg.MinSize = 128
	}
	if cfg.MaxSize <= 0 {
		cfg.MaxSize = 1500
	}
	if cfg.MaxSize < cfg.MinSize {
		cfg.MaxSize = cfg.MinSize
	}
	if cfg.BudgetCap <= 0 {
		cfg.BudgetCap = 128 * 1024
	}

	ci := &coverInjector{
		cfg:              cfg,
		inject:           inject,
		isClosing:        isClosing,
		minResetInterval: time.Duration(cfg.IdleTimeout) * time.Millisecond / 2,
		coverThreshold:   int64(1024*1024) + int64(randomInt(1<<20)),
	}
	ci.timer = time.AfterFunc(time.Duration(cfg.IdleTimeout)*time.Millisecond, ci.onIdle)
	ci.timer.Stop()
	return ci
}

func (ci *coverInjector) addBudget(realBytes int) {
	if ci.stopped.Load() {
		return
	}

	total := ci.totalSent.Add(int64(realBytes))
	if total >= ci.coverThreshold {
		ci.stopped.Store(true)
		return
	}

	ci.lastRealData.Store(time.Now().UnixNano())

	ci.mu.Lock()
	ci.budget += float64(realBytes) * ci.cfg.BudgetRatio
	if ci.budget > float64(ci.cfg.BudgetCap) {
		ci.budget = float64(ci.cfg.BudgetCap)
	}
	now := time.Now()
	if now.Sub(ci.lastReset) >= ci.minResetInterval {
		ci.timer.Reset(ci.jitterTimeout())
		ci.lastReset = now
	}
	ci.mu.Unlock()
}

func (ci *coverInjector) stop() {
	ci.stopped.Store(true)
	ci.mu.Lock()
	defer ci.mu.Unlock()
	ci.timer.Stop()
	ci.budget = 0
}

func (ci *coverInjector) onIdle() {
	if ci.stopped.Load() {
		return
	}

	ci.mu.Lock()

	if ci.isClosing() {
		ci.mu.Unlock()
		return
	}

	if ci.totalSent.Load() >= ci.coverThreshold {
		ci.budget = 0
		ci.stopped.Store(true)
		ci.mu.Unlock()
		return
	}

	lastRealNs := ci.lastRealData.Load()
	if lastRealNs > 0 {
		lastReal := time.Unix(0, lastRealNs)
		if time.Since(lastReal) < time.Duration(ci.cfg.IdleTimeout)*time.Millisecond {
			ci.budget *= 0.5
			ci.timer.Reset(ci.jitterTimeout())
			ci.mu.Unlock()
			return
		}
	}

	budget := ci.budget
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

	ci.mu.Unlock()

	payload := bytespool.Get(frameSize)[:frameSize]
	_, _ = coverRNG.Read(payload)
	frame := protocol.Frame{
		Type:    protocol.FrameCOVER,
		Length:  uint16(frameSize),
		Payload: payload,
	}
	_ = ci.inject(frame)
}

func (ci *coverInjector) coverFrameSizeRange() (minSize, maxSize int) {
	const smoothSpan = 1 << 20
	sent := ci.totalSent.Load()
	ratio := float64(min(sent, smoothSpan)) / float64(smoothSpan)

	cfgMin, cfgMax := ci.cfg.MinSize, ci.cfg.MaxSize
	span := float64(cfgMax - cfgMin)

	// 初始阶段以接近 cfgMin 的小尺寸为主,模拟空闲连接的小数据包特征;
	// 随累计真实流量平滑过渡到接近真实 DATA 帧的尺寸分布。
	// 默认配置(MinSize=128, MaxSize=1500)下:
	//   ratio=0 -> [128, 509],  ratio=1 -> [512, 1500]
	const (
		minSteadyRatio = 0.28
		maxStartRatio  = 0.278
	)
	minSteady := cfgMin + int(span*minSteadyRatio)
	maxStart := cfgMin + int(span*maxStartRatio)

	minSize = cfgMin + int(ratio*float64(minSteady-cfgMin))
	maxSize = maxStart + int(ratio*float64(cfgMax-maxStart))
	return
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
