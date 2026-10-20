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

// dialAttemptRecord 记录一次假拨号的地址与预算（ctx 截止时间与调用时刻之差，无截止时间时为 0）。
type dialAttemptRecord struct {
	addr   string
	budget time.Duration
}

// stubDialAttempt 记录每个候选的地址与预算，把实际拨号交给 behavior：
// 预算切分无法用真实网络稳定复现，只能在假拨号里"挂起"来模拟 SYN 黑洞。
func stubDialAttempt(t *testing.T, behavior func(ctx context.Context, addr string) (net.Conn, error)) (*[]dialAttemptRecord, *dialer) {
	t.Helper()
	var records []dialAttemptRecord
	d := newTestDialer()
	d.deps.attempt = func(_ *net.Dialer, ctx context.Context, _, addr string) (net.Conn, error) {
		rec := dialAttemptRecord{addr: addr}
		if deadline, ok := ctx.Deadline(); ok {
			rec.budget = time.Until(deadline)
		}
		records = append(records, rec)
		return behavior(ctx, addr)
	}
	return &records, d
}

func hangUntilBudget(ctx context.Context, addr string) (net.Conn, error) {
	<-ctx.Done()
	return nil, fmt.Errorf("dial %s: %w", addr, ctx.Err())
}

func refuseNow(_ context.Context, addr string) (net.Conn, error) {
	return nil, fmt.Errorf("dial %s: connection refused", addr)
}

// shrinkDialAttemptMinBudget 调小候选的最小预算，让测试用毫秒级总预算验证切分，不必等满 2s。
func shrinkDialAttemptMinBudget(d *dialer, budget time.Duration) {
	d.deps.attemptMinBudget = budget
}

func testAddrs(t *testing.T, raw ...string) []netip.Addr {
	t.Helper()
	addrs := make([]netip.Addr, 0, len(raw))
	for _, s := range raw {
		addrs = append(addrs, netip.MustParseAddr(s))
	}
	return addrs
}

// TestOrderByFamily 固定排序规则：首选族先出现、两族交错，族内保持解析器顺序（RFC 6724 已排过）。
func TestOrderByFamily(t *testing.T) {
	t.Parallel()

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
			t.Parallel()
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

// TestDialCandidatesInterleavesFamilies 验证 dialCandidates 端到端使用交错排序。
func TestDialCandidatesInterleavesFamilies(t *testing.T) {
	t.Parallel()

	_, d := stubResolveHost(t, []string{testPublicV6, testPublicV4}, nil)
	prefer := netip.MustParseAddr(testPublicV4)

	got, err := d.candidates(withPreferredFamily(t.Context(), prefer), "example.com:443")
	if err != nil {
		t.Fatalf("candidates: %v", err)
	}
	if len(got) != 2 || got[0] != prefer || got[1] != netip.MustParseAddr(testPublicV6) {
		t.Fatalf("candidates = %v, want [%v %v]", got, prefer, testPublicV6)
	}
}

// TestDialAddrsSharedBudget 验证整批候选共享一份拨号预算：各吃满一份 d.Timeout 的话，
// 3 个黑洞候选会串行吃掉 3×d.Timeout，而换候选本该只等一个子预算。
func TestDialAddrsSharedBudget(t *testing.T) {
	records, d := stubDialAttempt(t, hangUntilBudget)
	shrinkDialAttemptMinBudget(d, 40*time.Millisecond)

	const budget = 300 * time.Millisecond
	nd := outboundDialer(budget, 0)

	start := time.Now()
	_, err := d.dialAddrs(t.Context(), nd, "tcp", "example.com:443", testAddrs(t, "1.1.1.1", "1.1.1.2", "1.1.1.3"))
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
	if first := (*records)[0].budget; first > budget/3+60*time.Millisecond {
		t.Fatalf("first candidate got %v, want roughly one third of the budget (%v)", first, budget/3)
	}
	if last := (*records)[2].budget; last > budget+60*time.Millisecond {
		t.Fatalf("last candidate got %v, want the remaining budget (%v)", last, budget)
	}
}

// TestAttemptDeadline 钉住预算切分公式（与 net.Dialer 的 partialDeadline 同构）：剩余预算按
// 剩余候选数均分，低于 dialAttemptMinBudget（默认 2s）按下限给，剩余不足下限则全部用掉。
func TestAttemptDeadline(t *testing.T) {
	t.Parallel()

	now := time.Unix(0, 0)

	for _, tc := range []struct {
		name           string
		budget         time.Duration
		candidatesLeft int
		want           time.Duration
	}{
		{"均分高于下限", 9 * time.Second, 3, 3 * time.Second},
		{"均分低于下限：按下限给", 10 * time.Second, 10, 2 * time.Second},
		{"剩余预算本身低于下限：全部用掉", 1500 * time.Millisecond, 10, 1500 * time.Millisecond},
		{"只剩一个候选：拿到全部剩余", 9 * time.Second, 1, 9 * time.Second},
		{"预算已耗尽", 0, 5, 0},
		{"预算已超时", -time.Second, 5, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := attemptDeadline(now, now.Add(tc.budget), tc.candidatesLeft, defaultDialAttemptMinBudget)
			if want := now.Add(tc.want); !got.Equal(want) {
				t.Fatalf("attemptDeadline(budget=%v, candidatesLeft=%d) = %v, want %v",
					tc.budget, tc.candidatesLeft, got.Sub(now), tc.want)
			}
		})
	}
}

// TestDialAddrsBudgetFloor 验证最小预算：均分后低于 dialAttemptMinBudget 时按下限给，
// 候选不会被逐个试满。断言刻意只涉及与调度无关的事实——尝试次数取决于计时器粒度与 CI 负载，
// 精确的切分公式由 TestAttemptDeadline 覆盖。
func TestDialAddrsBudgetFloor(t *testing.T) {
	const (
		budget    = 100 * time.Millisecond
		minBudget = 40 * time.Millisecond
		// slack 容忍测量粒度：假拨号用 time.Until 读预算，只会比切分出的份额小。
		slack = 20 * time.Millisecond
	)
	records, d := stubDialAttempt(t, hangUntilBudget)
	shrinkDialAttemptMinBudget(d, minBudget)

	nd := outboundDialer(budget, 0)
	addrs := testAddrs(t, "1.1.1.1", "1.1.1.2", "1.1.1.3", "1.1.1.4", "1.1.1.5",
		"1.1.1.6", "1.1.1.7", "1.1.1.8", "1.1.1.9", "1.1.1.10")

	if _, err := d.dialAddrs(t.Context(), nd, "tcp", "example.com:443", addrs); err == nil {
		t.Fatal("dialAddrs should fail when every candidate hangs")
	}

	// 共享预算必须限制尝试次数：没有下限时每次只拿 100ms/10 = 10ms，足以试完 10 个候选。
	if n := len(*records); n >= len(addrs) {
		t.Fatalf("attempts = %d, want fewer than the %d candidates: the shared budget must bound the loop",
			n, len(addrs))
	}

	// 没有候选拿到超过下限的预算：既排除整份预算给第一个候选，也排除按候选数平摊。
	for i, rec := range *records {
		if rec.budget > minBudget+slack {
			t.Fatalf("attempt %d (%s) got %v, want at most one min-budget slice (%v): the split must not hand out a flat budget/candidates share",
				i+1, rec.addr, rec.budget, minBudget)
		}
	}
}

// TestDialAddrsBudgetExhaustedKeepsDialError 验证预算耗尽不返回 errClientGone：否则上层
// isTransientStreamError 会把真正的拨号故障静音成预期拆除。
func TestDialAddrsBudgetExhaustedKeepsDialError(t *testing.T) {
	_, d := stubDialAttempt(t, hangUntilBudget)
	shrinkDialAttemptMinBudget(d, 20*time.Millisecond)

	nd := outboundDialer(60*time.Millisecond, 0)
	_, err := d.dialAddrs(t.Context(), nd, "tcp", "example.com:443", testAddrs(t, "1.1.1.1", "1.1.1.2"))
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

// TestDialAddrsCallerGoneWinsOverBudget 验证调用方离开优先于预算：请求 ctx 失效即返回 errClientGone。
func TestDialAddrsCallerGoneWinsOverBudget(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	records, d := stubDialAttempt(t, func(_ context.Context, addr string) (net.Conn, error) {
		cancel() // 第一次拨号期间客户端离开
		return nil, fmt.Errorf("dial %s: operation was canceled", addr)
	})
	shrinkDialAttemptMinBudget(d, 50*time.Millisecond)

	nd := outboundDialer(5*time.Second, 0)
	_, err := d.dialAddrs(ctx, nd, "tcp", "example.com:443", testAddrs(t, "1.1.1.1", "1.1.1.2", "1.1.1.3"))
	if !errors.Is(err, errClientGone) {
		t.Fatalf("dialAddrs = %v, want errClientGone once the caller's context is gone", err)
	}
	if len(*records) != 1 {
		t.Fatalf("attempts = %d, want 1 (a gone caller must stop the loop)", len(*records))
	}
}

// TestDialAddrsWithoutTimeout 验证 d.Timeout <= 0 时不加整体预算，截止时间全由调用方 ctx 决定。
func TestDialAddrsWithoutTimeout(t *testing.T) {
	t.Parallel()

	records, d := stubDialAttempt(t, refuseNow)

	_, err := d.dialAddrs(t.Context(), &net.Dialer{}, "tcp", "example.com:443", testAddrs(t, "1.1.1.1", "1.1.1.2"))
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

// TestDialAddrsEmptyCandidates 验证空候选列表返回错误而不是 (nil, nil)。
func TestDialAddrsEmptyCandidates(t *testing.T) {
	t.Parallel()

	conn, err := newTestDialer().dialAddrs(t.Context(), outboundDialer(time.Second, 0), "tcp", "example.com:443", nil)
	if err == nil {
		t.Fatal("dialAddrs should reject an empty candidate list")
	}
	if conn != nil {
		t.Fatalf("conn = %v, want nil", conn)
	}
}

// TestDialAddrsFallbackKeepsBudget 验证候选失败后回退到下一个，成功路径不受子预算切分影响。
func TestDialAddrsFallbackKeepsBudget(t *testing.T) {
	conn := newStubConn(nil)
	t.Cleanup(func() { _ = conn.Close() })

	records, d := stubDialAttempt(t, func(_ context.Context, addr string) (net.Conn, error) {
		if addr == "1.1.1.2:443" {
			return conn, nil
		}
		return nil, fmt.Errorf("dial %s: connection refused", addr)
	})
	shrinkDialAttemptMinBudget(d, 20*time.Millisecond)

	got, err := d.dialAddrs(t.Context(), outboundDialer(time.Second, 0), "tcp", "example.com:443", testAddrs(t, "1.1.1.1", "1.1.1.2"))
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
