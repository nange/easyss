package http2

import (
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	sharedconfig "github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/transport"
)

// TestStatsConnsStatusConsistencyUnderShrink 用 shrinker goroutine
// （模拟 closeIdleLoop）压力测试调度器，同时让一个 stats 读取 goroutine
// （模拟 /stats 轮询）渲染每个池的 conns_status。若渲染出的条目数超过
// 并发报告的每池 Conns 值，或任一池渲染出的索引不是从 0 连续递增，
// 则测试失败。
func TestStatsConnsStatusConsistencyUnderShrink(t *testing.T) {
	slots := make([]*transportSlot, 6)
	for i := range slots {
		slots[i] = &transportSlot{idx: i}
	}
	sch := newScheduler(6, slots, 2, 1)
	sch.priority.liveCount.Store(1)
	sch.bulk.liveCount.Store(5)

	var over atomic.Int64
	var badIdx atomic.Int64
	var reads atomic.Int64
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		for {
			select {
			case <-done:
				return
			default:
			}
			sch.mu.Lock()
			sch.shrinkIdleLocked()
			sch.mu.Unlock()
			// 像新流到达那样重新生长。
			sch.grow(false)
		}
	}()

	go func() {
		defer wg.Done()
		for {
			select {
			case <-done:
				return
			default:
			}
			// 在调度器读锁下渲染，与生产 Stats() 快照完全一致：
			// shrink/grow 在写锁下交换删除槽位，不加锁的渲染会与
			// 数组交换产生竞争。
			sch.mu.RLock()
			pLive := int(sch.priority.liveCount.Load())
			bLive := int(sch.bulk.liveCount.Load())
			pStr := slotStatusString(sch.priority, pLive)
			bStr := slotStatusString(sch.bulk, bLive)
			sch.mu.RUnlock()
			pIdxs := parseIndices(pStr)
			bIdxs := parseIndices(bStr)
			if len(pIdxs) > pLive {
				over.Add(int64(len(pIdxs) - pLive))
			}
			if len(bIdxs) > bLive {
				over.Add(int64(len(bIdxs) - bLive))
			}
			for k, id := range pIdxs {
				if id != k {
					badIdx.Add(1)
					break
				}
			}
			for k, id := range bIdxs {
				if id != k {
					badIdx.Add(1)
					break
				}
			}
			reads.Add(1)
		}
	}()

	time.Sleep(200 * time.Millisecond)
	close(done)
	wg.Wait()
	t.Logf("reads=%d over_by_total=%d bad_idx_total=%d", reads.Load(), over.Load(), badIdx.Load())
	if over.Load() > 0 {
		t.Fatalf("conns_status rendered more entries than Conns: over=%d", over.Load())
	}
	if badIdx.Load() > 0 {
		t.Fatalf("conns_status indices are not consecutive from 0: bad=%d", badIdx.Load())
	}
}

// parseIndices 提取每条目的前导 "<index>:"，同时验证数组形状。
func parseIndices(s string) []int {
	if s == "[]" {
		return nil
	}
	body := strings.TrimSuffix(strings.TrimPrefix(s, "["), "]")
	parts := strings.Split(body, ", ")
	idxs := make([]int, 0, len(parts))
	for _, p := range parts {
		colon := strings.IndexByte(p, ':')
		n, err := strconv.Atoi(p[:colon])
		if err != nil {
			panic("malformed entry: " + p)
		}
		idxs = append(idxs, n)
	}
	return idxs
}

// TestGrowEventRingOrderAndCap 验证增长事件环形缓冲：最新在前、
// 上限为 maxGrowEvents、携带触发请求的 endpoint 与 target。
func TestGrowEventRingOrderAndCap(t *testing.T) {
	slots := make([]*transportSlot, 4)
	for i := range slots {
		slots[i] = &transportSlot{idx: i}
	}
	tr := &http2Transport{sched: newScheduler(4, slots, 4, 2)}

	for i := range maxGrowEvents + 4 {
		tr.recordGrowEvent("bulk", int32(i), transport.OpenRequest{
			Endpoint: sharedconfig.EndpointUDP,
			Target:   "8.8.8.8:53",
		})
	}

	evs := tr.Stats().GrowEvents
	if len(evs) != maxGrowEvents {
		t.Fatalf("GrowEvents = %d, want %d (ring bound)", len(evs), maxGrowEvents)
	}
	// 最新在前：最后记录的事件（live = maxGrowEvents+3）位于快照头部，
	// 存留最久的（live = 4）位于尾部。
	if evs[0].Live != maxGrowEvents+3 {
		t.Fatalf("head event live = %d, want %d (newest first)", evs[0].Live, maxGrowEvents+3)
	}
	if evs[0].Pool != "bulk" || evs[0].Endpoint != sharedconfig.EndpointUDP || evs[0].Target != "8.8.8.8:53" {
		t.Fatalf("head event fields wrong: %+v", evs[0])
	}
	if evs[len(evs)-1].Live != 4 {
		t.Fatalf("tail event live = %d, want 4 (oldest surviving)", evs[len(evs)-1].Live)
	}
}

// TestGrowEventRingConcurrent 压力测试增长事件环形缓冲：一个生产者
// goroutine 记录事件，同时一个读取 goroutine 快照 Stats()——
// 必须无竞争，且绝不超过环形缓冲上限。
func TestGrowEventRingConcurrent(t *testing.T) {
	slots := make([]*transportSlot, 4)
	for i := range slots {
		slots[i] = &transportSlot{idx: i}
	}
	tr := &http2Transport{sched: newScheduler(4, slots, 4, 2)}

	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-done:
				return
			default:
			}
			tr.recordGrowEvent("bulk", 3, transport.OpenRequest{
				Endpoint: sharedconfig.EndpointTCP,
				Target:   "1.2.3.4:53",
			})
		}
	}()
	go func() {
		defer wg.Done()
		for {
			select {
			case <-done:
				return
			default:
			}
			_ = tr.Stats()
		}
	}()

	time.Sleep(200 * time.Millisecond)
	close(done)
	wg.Wait()

	if got := len(tr.Stats().GrowEvents); got > maxGrowEvents {
		t.Fatalf("GrowEvents = %d, want <= %d", got, maxGrowEvents)
	}
}
