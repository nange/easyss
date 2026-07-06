package stats

import (
	"sync/atomic"
	"time"

	"github.com/nange/easyss/v3/log"
)

const (
	stallThreshold int64 = 1 << 20
	stallLogMinGap       = 60
)

type StreamMeter struct {
	component    string
	target       string
	total        atomic.Int64
	last         atomic.Int64
	state        atomic.Value
	lastLoggedAt atomic.Int64
	done         chan struct{}
}

func NewStreamMeter(component, target string) *StreamMeter {
	m := &StreamMeter{
		component: component,
		target:    target,
		done:      make(chan struct{}),
	}
	m.state.Store("open")
	go m.loop()
	return m
}

func (m *StreamMeter) Add(n int, state string) {
	if n > 0 {
		m.total.Add(int64(n))
	}
	m.SetState(state)
}

func (m *StreamMeter) SetState(state string) {
	if state != "" {
		m.state.Store(state)
	}
}

func (m *StreamMeter) Close() {
	close(m.done)
}

func (m *StreamMeter) loop() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			total := m.total.Load()
			last := m.last.Swap(total)
			if total >= stallThreshold && total == last {
				now := time.Now().Unix()
				if prev := m.lastLoggedAt.Load(); now-prev >= stallLogMinGap {
					m.lastLoggedAt.Store(now)
					log.Info("[STREAM] downstream stalled", "component", m.component, "target", m.target, "bytes", total, "state", m.state.Load())
				}
			}
		case <-m.done:
			return
		}
	}
}
