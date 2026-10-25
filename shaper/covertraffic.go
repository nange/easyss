package shaper

import (
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nange/easyss/v3/protocol"
	"github.com/nange/easyss/v3/util/bytespool"
)

type coverInjector struct {
	cfg Cover
	mu  sync.Mutex
	// rng 归本 injector 所有，在 ci.mu 下使用，避免所有流共用一把全局锁。
	rng              *rand.ChaCha8
	budget           float64
	timer            *time.Timer
	inject           func(f protocol.Frame) error
	isClosing        func() bool
	lastReset        time.Time
	lastRealData     atomic.Int64
	minResetInterval time.Duration
	totalSent        atomic.Int64
	stopped          atomic.Bool
}

// 配置必须已经过 Config.Normalize——cover 默认值的唯一出处；BudgetRatio 为零时禁用。
func newCoverInjector(cfg Cover, inject func(protocol.Frame) error, isClosing func() bool) *coverInjector {
	if cfg.BudgetRatio == 0 {
		return nil
	}

	ci := &coverInjector{
		cfg:              cfg,
		rng:              newSeededChaCha8(),
		inject:           inject,
		isClosing:        isClosing,
		minResetInterval: time.Duration(cfg.IdleTimeout) * time.Millisecond / 2,
	}
	ci.timer = time.AfterFunc(time.Duration(cfg.IdleTimeout)*time.Millisecond, ci.onIdle)
	ci.timer.Stop()
	return ci
}

func (ci *coverInjector) addBudget(realBytes int) {
	if ci.stopped.Load() {
		return
	}

	ci.totalSent.Add(int64(realBytes))
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

	lastRealNs := ci.lastRealData.Load()
	if lastRealNs > 0 {
		lastReal := time.Unix(0, lastRealNs)
		if time.Since(lastReal) < time.Duration(ci.cfg.IdleTimeout)*time.Millisecond {
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
	// onIdle 可能在上一次回调的 unlock 之后再次触发，RNG 仍须串行化。
	ci.mu.Lock()
	_, _ = ci.rng.Read(payload)
	ci.mu.Unlock()
	// NewFrameWithPayload 直接包装池化缓冲区而不复制：整形器在追加该帧后
	// 会将这个缓冲区原样归还池。
	frame := protocol.NewFrameWithPayload(protocol.FrameCOVER, payload)
	_ = ci.inject(frame)
}

func (ci *coverInjector) coverFrameSizeRange() (minSize, maxSize int) {
	const smoothSpan = 1 << 20
	sent := ci.totalSent.Load()
	ratio := float64(min(sent, smoothSpan)) / float64(smoothSpan)

	cfgMin, cfgMax := ci.cfg.MinSize, ci.cfg.MaxSize
	span := float64(cfgMax - cfgMin)

	// 初始阶段以接近 cfgMin 的小尺寸模拟空闲连接，随累计真实流量平滑过渡到
	// 接近真实 DATA 帧的尺寸分布，避免 cover 帧在流量画像上过于显眼。
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
