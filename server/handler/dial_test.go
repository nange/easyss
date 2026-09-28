package handler

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"
)

// dialAttemptRecord 是一次假拨号的记录：拨给哪个地址，以及本次拨号拿到的预算
// （ctx 截止时间与调用时刻之差；调用方没有截止时间时为 0）。
type dialAttemptRecord struct {
	addr   string
	budget time.Duration
}

// stubDialAttempt 替换 dialAttempt，记录每个候选拿到的地址与预算，并把实际拨号
// 交给 behavior。预算切分是这里唯一无法用真实网络稳定复现的行为，因此测试注入
// 确定性的假拨号（可以在预算内"挂起"，模拟被墙 IP 的 SYN 黑洞）。
func stubDialAttempt(t *testing.T, behavior func(ctx context.Context, addr string) (net.Conn, error)) *[]dialAttemptRecord {
	t.Helper()
	var records []dialAttemptRecord
	prev := dialAttempt
	dialAttempt = func(_ *net.Dialer, ctx context.Context, _, addr string) (net.Conn, error) {
		rec := dialAttemptRecord{addr: addr}
		if deadline, ok := ctx.Deadline(); ok {
			rec.budget = time.Until(deadline)
		}
		records = append(records, rec)
		return behavior(ctx, addr)
	}
	t.Cleanup(func() { dialAttempt = prev })
	return &records
}

// hangUntilBudget 模拟 SYN 黑洞：一直阻塞到本次预算耗尽，再返回超时错误。
func hangUntilBudget(ctx context.Context, addr string) (net.Conn, error) {
	<-ctx.Done()
	return nil, fmt.Errorf("dial %s: %w", addr, ctx.Err())
}

// refuseNow 模拟立刻被拒绝的候选（连接被 RST / 端口未监听）。
func refuseNow(_ context.Context, addr string) (net.Conn, error) {
	return nil, fmt.Errorf("dial %s: connection refused", addr)
}

// shrinkDialAttemptMinBudget 把候选的最小预算调小，使测试可以用毫秒级的总预算
// 验证切分，而不必真的等满 2s。
func shrinkDialAttemptMinBudget(t *testing.T, d time.Duration) {
	t.Helper()
	prev := dialAttemptMinBudget
	dialAttemptMinBudget = d
	t.Cleanup(func() { dialAttemptMinBudget = prev })
}

func testAddrs(t *testing.T, raw ...string) []netip.Addr {
	t.Helper()
	addrs := make([]netip.Addr, 0, len(raw))
	for _, s := range raw {
		addrs = append(addrs, netip.MustParseAddr(s))
	}
	return addrs
}

// TestOrderByFamily 固定候选的排序规则：首选族先出现，两族交错，族内保持解析器
// 给出的顺序（RFC 6724 已经排过），无偏好时原样返回。
func TestOrderByFamily(t *testing.T) {
	v4, v6 := netip.MustParseAddr(testPublicV4), netip.MustParseAddr(testPublicV6)
	v4b, v6b := netip.MustParseAddr("93.184.216.35"), netip.MustParseAddr("2606:2800:220:1:248:1893:25c8:1947")

	tests := []struct {
		name   string
		addrs  []netip.Addr
		prefer netip.Addr
		want   []netip.Addr
	}{
		{
			name:   "首选 ipv4 时两族交错",
			addrs:  []netip.Addr{v6, v6b, v4, v4b},
			prefer: v4,
			want:   []netip.Addr{v4, v6, v4b, v6b},
		},
		{
			name:   "首选 ipv6 时两族交错",
			addrs:  []netip.Addr{v4, v4b, v6, v6b},
			prefer: v6,
			want:   []netip.Addr{v6, v4, v6b, v4b},
		},
		{
			name:   "无偏好保持原序",
			addrs:  []netip.Addr{v6, v4},
			prefer: netip.Addr{},
			want:   []netip.Addr{v6, v4},
		},
		{
			name:   "只有一个候选不重排",
			addrs:  []netip.Addr{v4},
			prefer: v6,
			want:   []netip.Addr{v4},
		},
		{
			name:   "只有另一族时依旧可连",
			addrs:  []netip.Addr{v6, v6b},
			prefer: v4,
			want:   []netip.Addr{v6, v6b},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := make([]netip.Addr, len(tt.addrs))
			copy(before, tt.addrs)

			got := orderByFamily(tt.addrs, tt.prefer)
			if len(got) != len(tt.want) {
				t.Fatalf("orderByFamily = %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("orderByFamily = %v, want %v", got, tt.want)
				}
			}
			// 入参是 ctx 里共享的切片，绝不能被就地修改。
			for i := range before {
				if before[i] != tt.addrs[i] {
					t.Fatalf("orderByFamily modified its input: %v, want %v", tt.addrs, before)
				}
			}
		})
	}
}

// TestDialCandidatesInterleavesFamilies 验证 dialCandidates 端到端地使用交错排序：
// 首选族的第一个地址在最前，另一个族的第一个地址紧随其后。
func TestDialCandidatesInterleavesFamilies(t *testing.T) {
	stubResolveHost(t, []string{testPublicV6, testPublicV4}, nil)
	prefer := netip.MustParseAddr(testPublicV4)

	got, err := dialCandidates(withPreferredFamily(t.Context(), prefer), "example.com:443")
	if err != nil {
		t.Fatalf("dialCandidates: %v", err)
	}
	if len(got) != 2 || got[0] != prefer || got[1] != netip.MustParseAddr(testPublicV6) {
		t.Fatalf("candidates = %v, want [%v %v]", got, prefer, testPublicV6)
	}
}

// TestDialAddrsSharedBudget 验证整批候选共享一份拨号预算：每个候选只拿到剩余预算
// 的一部分（而不是各吃满一份 d.Timeout），预算用尽后停止尝试，总耗时回到单份
// d.Timeout 之内。旧行为下 3 个黑洞候选会串行吃掉 3×d.Timeout。
func TestDialAddrsSharedBudget(t *testing.T) {
	shrinkDialAttemptMinBudget(t, 40*time.Millisecond)
	records := stubDialAttempt(t, hangUntilBudget)

	const budget = 300 * time.Millisecond
	dialer := outboundDialer(budget, 0)

	start := time.Now()
	_, err := dialAddrs(t.Context(), dialer, "tcp", "example.com:443", testAddrs(t, "1.1.1.1", "1.1.1.2", "1.1.1.3"))
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("dialAddrs should fail when every candidate hangs")
	}
	if len(*records) != 3 {
		t.Fatalf("attempts = %d, want 3 (every candidate must be tried before the budget runs out)", len(*records))
	}
	if elapsed > 2*budget {
		t.Fatalf("dialAddrs took %v, want at most one shared budget (%v) instead of one per candidate", elapsed, budget)
	}
	// 第一个候选只拿 1/3 的预算，最后一个拿到剩余的全部：这是"换候选只需等一个
	// 子预算"的依据。
	if first := (*records)[0].budget; first > budget/3+60*time.Millisecond {
		t.Fatalf("first candidate got %v, want roughly one third of the budget (%v)", first, budget/3)
	}
	if last := (*records)[2].budget; last > budget+60*time.Millisecond {
		t.Fatalf("last candidate got %v, want the remaining budget (%v)", last, budget)
	}
}

// TestDialAddrsBudgetFloor 验证单个候选的最小预算：按候选数均分后低于
// dialAttemptMinBudget 时按最小值给（剩余预算不足时给剩余量），因此尝试次数远小于
// 候选数，并且每个候选拿到的是下限而不是"总预算/候选数"。
func TestDialAddrsBudgetFloor(t *testing.T) {
	const (
		budget    = 100 * time.Millisecond
		minBudget = 40 * time.Millisecond
	)
	shrinkDialAttemptMinBudget(t, minBudget)
	records := stubDialAttempt(t, hangUntilBudget)

	dialer := outboundDialer(budget, 0)
	addrs := testAddrs(t, "1.1.1.1", "1.1.1.2", "1.1.1.3", "1.1.1.4", "1.1.1.5",
		"1.1.1.6", "1.1.1.7", "1.1.1.8", "1.1.1.9", "1.1.1.10")

	if _, err := dialAddrs(t.Context(), dialer, "tcp", "example.com:443", addrs); err == nil {
		t.Fatal("dialAddrs should fail when every candidate hangs")
	}

	// 100ms 预算按 40ms 一片只能切出 2~4 次尝试（最后一片按剩余量给，切分点落在
	// 计时器粒度上时会多切一次）；没有下限时这里会试满 10 个候选。
	if n := len(*records); n < 2 || n > 4 {
		t.Fatalf("attempts = %d, want the budget spent in min-budget slices (2..4) instead of one per candidate (%d)",
			n, len(addrs))
	}

	// 平摊（100ms/10 = 10ms）与下限（40ms）的区别：至少要有一个候选拿到下限级别
	// 的预算，否则说明切分退回了平均分配。
	var largest time.Duration
	for _, rec := range *records {
		largest = max(largest, rec.budget)
	}
	if largest < 30*time.Millisecond {
		t.Fatalf("largest per-candidate budget = %v, want the dialAttemptMinBudget floor (%v)", largest, minBudget)
	}
}

// TestDialAddrsBudgetExhaustedKeepsDialError 验证预算耗尽不是"客户端离开"：返回的
// 必须是最后一个真实的拨号错误，否则上层的 isTransientStreamError 会把真正的拨号
// 故障静音成预期拆除。
func TestDialAddrsBudgetExhaustedKeepsDialError(t *testing.T) {
	shrinkDialAttemptMinBudget(t, 20*time.Millisecond)
	stubDialAttempt(t, hangUntilBudget)

	dialer := outboundDialer(60*time.Millisecond, 0)
	_, err := dialAddrs(t.Context(), dialer, "tcp", "example.com:443", testAddrs(t, "1.1.1.1", "1.1.1.2"))
	if err == nil {
		t.Fatal("dialAddrs should fail when the budget runs out")
	}
	if errors.Is(err, errClientGone) {
		t.Fatalf("dialAddrs = %v, want the last dial error rather than errClientGone", err)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("dialAddrs = %v, want the dialer's deadline error", err)
	}
}

// TestDialAddrsCallerGoneWinsOverBudget 验证调用方离开优先于预算：即使整体预算还
// 没到，只要请求 ctx 失效就必须返回 errClientGone（客户端拆除走静默路径）。
func TestDialAddrsCallerGoneWinsOverBudget(t *testing.T) {
	shrinkDialAttemptMinBudget(t, 50*time.Millisecond)

	ctx, cancel := context.WithCancel(t.Context())
	records := stubDialAttempt(t, func(_ context.Context, addr string) (net.Conn, error) {
		cancel() // 第一次拨号期间客户端离开
		return nil, fmt.Errorf("dial %s: operation was canceled", addr)
	})

	dialer := outboundDialer(5*time.Second, 0)
	_, err := dialAddrs(ctx, dialer, "tcp", "example.com:443", testAddrs(t, "1.1.1.1", "1.1.1.2", "1.1.1.3"))
	if !errors.Is(err, errClientGone) {
		t.Fatalf("dialAddrs = %v, want errClientGone once the caller's context is gone", err)
	}
	if len(*records) != 1 {
		t.Fatalf("attempts = %d, want 1 (a gone caller must stop the loop)", len(*records))
	}
}

// TestDialAddrsWithoutTimeout 验证 d.Timeout <= 0 时不加整体预算：候选仍逐个尝试，
// 截止时间完全由调用方 ctx 决定（此时不该给候选编造一个 deadline）。
func TestDialAddrsWithoutTimeout(t *testing.T) {
	records := stubDialAttempt(t, refuseNow)

	_, err := dialAddrs(t.Context(), &net.Dialer{}, "tcp", "example.com:443", testAddrs(t, "1.1.1.1", "1.1.1.2"))
	if err == nil {
		t.Fatal("dialAddrs should return the last failure")
	}
	if len(*records) != 2 {
		t.Fatalf("attempts = %d, want every candidate tried", len(*records))
	}
	for i, rec := range *records {
		if rec.budget != 0 {
			t.Fatalf("attempt %d saw a %v deadline, want none without a configured timeout", i, rec.budget)
		}
	}
}

// TestDialAddrsEmptyCandidates 验证空候选列表返回错误而不是 (nil, nil)：后者会让
// 调用方拿到一个 nil 连接。
func TestDialAddrsEmptyCandidates(t *testing.T) {
	conn, err := dialAddrs(t.Context(), outboundDialer(time.Second, 0), "tcp", "example.com:443", nil)
	if err == nil {
		t.Fatal("dialAddrs should reject an empty candidate list")
	}
	if conn != nil {
		t.Fatalf("conn = %v, want nil", conn)
	}
}

// TestDialAddrsFallbackKeepsBudget 验证候选失败后仍然回退到下一个，并且整体耗时
// 受共享预算约束（成功路径不受子预算切分的负面影响）。
func TestDialAddrsFallbackKeepsBudget(t *testing.T) {
	shrinkDialAttemptMinBudget(t, 20*time.Millisecond)
	conn := newStubConn(nil)
	t.Cleanup(func() { _ = conn.Close() })

	records := stubDialAttempt(t, func(_ context.Context, addr string) (net.Conn, error) {
		if addr == "1.1.1.2:443" {
			return conn, nil
		}
		return nil, fmt.Errorf("dial %s: connection refused", addr)
	})

	got, err := dialAddrs(t.Context(), outboundDialer(time.Second, 0), "tcp", "example.com:443", testAddrs(t, "1.1.1.1", "1.1.1.2"))
	if err != nil {
		t.Fatalf("dialAddrs: %v", err)
	}
	if got != conn {
		t.Fatalf("conn = %v, want the second candidate's connection", got)
	}
	if len(*records) != 2 {
		t.Fatalf("attempts = %d, want 2", len(*records))
	}
}
