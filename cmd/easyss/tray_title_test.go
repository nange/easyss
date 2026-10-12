//go:build !headless

package main

import (
	"math"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// titleWidthForTest 用与生产代码完全相同的度量函数测量整段文本的宽度（单位 pt），
// 用来断言"指标列落在同一列"这一视觉契约：填充与地址必须在同一坐标系里相加。
func titleWidthForTest(s string) float64 {
	return measureTextWidth(s)
}

// metricsColumnForTest 返回标题里指标（"60ms"/"↓..."）的起始列位置。
func metricsColumnForTest(t *testing.T, title string) float64 {
	t.Helper()
	idx := -1
	for _, marker := range []string{"ms", "↓"} {
		if i := strings.Index(title, marker); i >= 0 && (idx < 0 || i < idx) {
			idx = i
		}
	}
	require.GreaterOrEqual(t, idx, 0, "标题里找不到指标: %q", title)
	if strings.HasPrefix(title[idx:], "ms") {
		// 回退到数字起点
		start := idx
		for start > 0 && title[start-1] >= '0' && title[start-1] <= '9' {
			start--
		}
		idx = start
	}
	// 必须测量整段前缀（而不是逐字符相加）：菜单排版对每个字形做整数量化，
	// 逐字符求与会系统性偏大 1~2%。
	return titleWidthForTest(title[:idx])
}

// TestFormatTitleAlignsMetricsColumn 固定这个问题本身：不管地址是 IP 字面量还是
// 域名，指标都要从同一列开始（此前用 "\t" 时，28pt 的默认 tab 间隔让间隔随地址
// 长度乱跳，IP 看起来"贴着"地址）。
func TestFormatTitleAlignsMetricsColumn(t *testing.T) {
	addrs := []string{
		"1.2.3.4:443",
		"203.0.113.9:443",
		"cn2.example.net:443",
		"server.example.com:443",
		"[2001:db8::1]:443",
		"edge.example.co.jp:8443",
	}

	var columns []float64
	for _, addr := range addrs {
		title := formatTitle(addr, 60, "649 B/s")
		require.NotContains(t, title, "\t", "不再依赖 tab 展开: %q", title)
		require.True(t, strings.HasPrefix(title, addr), "标题必须以地址开头: %q", title)
		require.Contains(t, title, "↓649 B/s", "指标不能丢: %q", title)

		column := metricsColumnForTest(t, title)
		require.GreaterOrEqual(t, column, serverColumnWidth-0.5,
			"地址 %q 的指标列早于目标列", addr)
		require.LessOrEqual(t, column, serverColumnWidth+columnStep+0.5,
			"地址 %q 的指标列超出第一个量化列", addr)
		columns = append(columns, column)
	}

	// 所有列位置都必须落在 168 + n*16 的量化列上（±半个最细一级空格）。
	for _, column := range columns {
		steps := (column - serverColumnWidth) / columnStep
		require.InDelta(t, math.Round(steps), steps, 0.05,
			"列位置 %.2f 必须落在量化列上", column)
	}

	// 宽度在 serverColumnWidth-minMetricsGap 以内的地址共用同一列，
	// 这是"IP 与域名看起来一样"的核心：它们都是绝大多数的服务器地址。
	for i, addr := range addrs {
		if measureTextWidth(addr)+minMetricsGap > serverColumnWidth {
			continue
		}
		require.InDelta(t, serverColumnWidth, columns[i], 0.5,
			"地址 %q 必须落在基准指标列上", addr)
	}
}

// TestFormatTitlePadsLongAddressWithMinimalGap 覆盖地址本身就超过目标列的情况：
// 地址先被截断（保证不超 maxAddressWidth），列位置随之右移，但地址与指标之间的
// 可见间隔不得小于 minMetricsGap（不允许指标贴着地址）。
func TestFormatTitlePadsLongAddressWithMinimalGap(t *testing.T) {
	addr := "very.long.hostname.for.a.branch.office.example.com:443"
	require.Greater(t, titleWidthForTest(addr), serverColumnWidth, "用例前提：地址超出目标列")

	title := formatTitle(addr, 60, "649 B/s")
	column := metricsColumnForTest(t, title)

	// 去掉填充后剩下的就是真正显示的（被截断的）地址。
	truncated := strings.TrimRight(title[:strings.Index(title, "60ms")], "\u2003\u2002\u200a ")
	require.True(t, strings.HasSuffix(truncated, "…"), "截断地址需要省略号: %q", truncated)
	require.LessOrEqual(t, titleWidthForTest(truncated), maxAddressWidth+0.5,
		"地址必须被截到显示上限内: %q", truncated)

	gap := column - titleWidthForTest(truncated)
	require.GreaterOrEqual(t, gap, minMetricsGap-0.5, "长地址也必须留出最小间隔")
	require.LessOrEqual(t, gap, minMetricsGap+columnStep+0.5,
		"列位置按 columnStep 量化，间隔最多比最小值多一个步长")
}

// TestFormatTitleWithoutMetrics 指标都拿不到时保持纯地址，不产生多余留白。
func TestFormatTitleWithoutMetrics(t *testing.T) {
	require.Equal(t, "1.2.3.4:443", formatTitle("1.2.3.4:443", 0, ""))
	require.Equal(t, "1.2.3.4:443", formatTitle("1.2.3.4:443", -1, ""))
}

// TestFormatTitleMetricsVariants 只要有一项指标可用就排到指标列：
// 只有 RTT、只有下载速度、以及两者都有。
func TestFormatTitleMetricsVariants(t *testing.T) {
	for _, tc := range []struct {
		name      string
		rttMs     float64
		downSpeed string
		metrics   string
	}{
		{name: "只有 RTT", rttMs: 436, metrics: "436ms"},
		{name: "只有下载速度", downSpeed: "27 B/s", metrics: "↓27 B/s"},
		{name: "两者都有", rttMs: 60, downSpeed: "649 B/s", metrics: "60ms  ↓649 B/s"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			title := formatTitle("1.2.3.4:443", tc.rttMs, tc.downSpeed)
			require.True(t, strings.HasSuffix(title, tc.metrics), "标题尾部: %q", title)
			require.InDelta(t, serverColumnWidth, metricsColumnForTest(t, title), 0.5)
		})
	}
}

// TestMeasureTextWidthFollowsRealGlyphWidths 确保宽度度量不是"按字符个数算"：
// 比例字体下 "1" 比 "0" 窄、"." 比 "m" 窄，度量必须跟着走，
// 否则列对齐会在不同地址上产生可见偏差。
func TestMeasureTextWidthFollowsRealGlyphWidths(t *testing.T) {
	require.Less(t, measureTextWidth("1"), measureTextWidth("0"))
	require.Less(t, measureTextWidth("."), measureTextWidth("m"))
	require.Less(t, measureTextWidth("i"), measureTextWidth("W"))
	require.Greater(t, measureTextWidth(" "), 0.0)
}

// TestTruncateToWidthKeepsEllipsis 超长地址截断后必须带省略号，且宽度不再超限。
func TestTruncateToWidthKeepsEllipsis(t *testing.T) {
	addr := "a.very.long.hostname.for.a.branch.office.example.com:443"
	got := truncateToWidth(addr, maxAddressWidth, "…")
	require.True(t, strings.HasSuffix(got, "…"), "截断结果需要省略号: %q", got)
	require.LessOrEqual(t, measureTextWidth(got), maxAddressWidth)
	require.True(t, strings.HasPrefix(addr, strings.TrimSuffix(got, "…")), "必须保留地址前缀: %q", got)
	require.Equal(t, "short.example:443", truncateToWidth("short.example:443", maxAddressWidth, "…"))
}

// TestTitlePadNeverOvershoots 填充只允许为了更接近目标宽度而略微超过（最多半个
// 最细一级空格），不允许出现"把地址推过目标列"的粗放填充。
func TestTitlePadNeverOvershoots(t *testing.T) {
	for _, target := range []float64{3, 7.5, 12.9, 30.2, 61.7, 120.4, 167.9} {
		pad := titlePad(target)
		width := titleWidthForTest(pad)
		require.LessOrEqual(t, width, target+0.75, "填充 %q 超出目标 %.1f", pad, target)
		require.Greater(t, width, target-0.5, "填充 %q 离目标 %.1f 太远", pad, target)
	}
}
