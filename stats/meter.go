package stats

import (
	"sync"
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
	// done 停止观察 goroutine（若已启动）；loopStarted 保证它至多启动一次，并让 Close 能区分
	// "已启动、需要等待它退出"与"从未启动、不能等"。
	done         chan struct{}
	loopStarted  atomic.Bool
	loopFinished chan struct{}
	closeOnce    sync.Once
}

// NewStreamMeter 创建一条流的字节计数与停顿探测器。观察 goroutine 不在构造时启动：停顿判定
// 要求 total ≥ stallThreshold，绝大多数流（短命流、空闲长连接、心跳流）一生都用不到它，惰性
// 化因此省掉每条流一个 goroutine 加一个 5s ticker，且不改变可观测语义。
func NewStreamMeter(component, target string) *StreamMeter {
	m := &StreamMeter{
		component:    component,
		target:       target,
		done:         make(chan struct{}),
		loopFinished: make(chan struct{}),
	}
	m.state.Store("open")
	return m
}

func (m *StreamMeter) Add(n int, state string) {
	if n > 0 {
		total := m.total.Add(int64(n))
		// 先做只读的 Load 再 CAS：total 只会继续增长，少了这层短路，热路径上每次 Add
		// 都要付一次注定失败的原子 RMW；CAS 仍负责并发下的唯一性。
		if total >= stallThreshold && !m.loopStarted.Load() && m.loopStarted.CompareAndSwap(false, true) {
			go m.loop()
		}
	}
	m.SetState(state)
}

func (m *StreamMeter) SetState(state string) {
	if state != "" {
		m.state.Store(state)
	}
}

func (m *StreamMeter) Bytes() int64 {
	return m.total.Load()
}

// Close 停止停顿探测并等待观察 goroutine 退出，幂等。只有真正启动过 goroutine 时才等待：
// 未启动时 loopFinished 永远不会关闭，在那里等待就是永久阻塞。
func (m *StreamMeter) Close() {
	m.closeOnce.Do(func() { close(m.done) })
	if m.loopStarted.Load() {
		<-m.loopFinished
	}
}

func (m *StreamMeter) loop() {
	defer close(m.loopFinished)
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
