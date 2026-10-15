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
	// done 停止观察 goroutine（若已启动）。
	done chan struct{}
	// loopStarted 保证观察 goroutine 至多启动一次，并让 Close 能区分
	// "已启动、需要等待它退出"与"从未启动、不能等"（见 Close）。
	loopStarted  atomic.Bool
	loopFinished chan struct{}
	closeOnce    sync.Once
}

// NewStreamMeter 创建一条流的字节计数与停顿探测器。
//
// 观察 goroutine **不在构造时启动**：停顿判定要求 total ≥ stallThreshold(1MB)，
// 在那之前计数器读数没有任何意义，因此绝大多数流（短命流、空闲的长连接、
// 心跳流）一生都用不到它。此前每条 TCP 流都无条件带一个 goroutine 加一个 5s
// ticker，而它每次都只是空转——每条流约 1KB 常驻加一次每 5s 的唤醒，在成百
// 上千条并发流上纯属浪费。惰性化不改变可观测语义：从未越过阈值的流，此前也
// 永远不会打出停顿日志。
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
		// 越过阈值之后观察者才有可判定的事可做。先做一次只读的 Load 再 CAS：
		// total 只会继续增长，少了这层短路，热路径上每次 Add 都要付一次注定
		// 失败的原子 RMW。CAS 仍然负责并发下的唯一性（Load 为 false 也不代表
		// 我们抢到了启动权）。
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

// Bytes 返回该流中继的总字节数。
func (m *StreamMeter) Bytes() int64 {
	return m.total.Load()
}

// Close 停止停顿探测，并等待观察 goroutine（若已启动）退出。它是幂等的。
//
// 只有真正启动过 goroutine 时才等待：未启动时 loopFinished 永远不会关闭，
// 在那里等待就是永久阻塞。
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
