//go:build !headless

package tray

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestFormatTitleWithoutMetrics 指标都拿不到时保持纯标签，不产生多余留白。
func TestFormatTitleWithoutMetrics(t *testing.T) {
	t.Parallel()

	require.Equal(t, "1.2.3.4:443", formatTitle("1.2.3.4:443", 0, "", 120))
	require.Equal(t, "1.2.3.4:443", formatTitle("1.2.3.4:443", -1, "", 120))
}

// TestFormatTitleKeepsMetrics 只要有一项指标可用就留在标题里：只有 RTT、只有下载速度、
// 以及两者都有。指标的排布方式按平台不同，这里只约束"标签 + 指标"这个公共契约。
func TestFormatTitleKeepsMetrics(t *testing.T) {
	t.Parallel()

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
			title := formatTitle("1.2.3.4:443", tc.rttMs, tc.downSpeed, 120)
			require.True(t, strings.HasPrefix(title, "1.2.3.4:443"), "标题必须以标签开头: %q", title)
			require.True(t, strings.HasSuffix(title, tc.metrics), "标题尾部: %q", title)
		})
	}
}

// TestFormatTitleTruncatesLongLabel 超长标签必须先截断再排版，否则会把指标挤出菜单可见范围。
func TestFormatTitleTruncatesLongLabel(t *testing.T) {
	t.Parallel()

	label := "very.long.hostname.for.a.branch.office.example.com:443"
	title := formatTitle(label, 60, "649 B/s", 0)

	require.NotContains(t, title, label, "长标签必须被截断: %q", title)
	require.Contains(t, title, "…", "截断后要带省略号: %q", title)
	require.True(t, strings.HasSuffix(title, "649 B/s"), "指标不能丢: %q", title)
}

// TestMeasureTextWidthFollowsRealGlyphWidths 确保宽度度量不是"按字符个数算"：
// 比例字体下 "1" 比 "0" 窄、"." 比 "m" 窄，宽度表必须跟着走，
// 否则对齐和截断会在不同标签上产生可见偏差。
func TestMeasureTextWidthFollowsRealGlyphWidths(t *testing.T) {
	t.Parallel()

	require.Less(t, measureTextWidth("1"), measureTextWidth("0"))
	require.Less(t, measureTextWidth("."), measureTextWidth("m"))
	require.Less(t, measureTextWidth("i"), measureTextWidth("W"))
	require.Greater(t, measureTextWidth(" "), 0.0)
}

// TestMeasureTextWidthEstimatesIDNAsFullWidth 固化"表外字符按全角（1em）估算"：
// 13pt 菜单字体下 CJK 字形实测 ≈12.9pt，不能被当成半角（≈7pt）而低估一半——
// 低估会让超长 IDN 不触发截断，列宽也会被低估。
func TestMeasureTextWidthEstimatesIDNAsFullWidth(t *testing.T) {
	t.Parallel()

	cjk := measureTextWidth("例")
	require.InDelta(t, 12.9, cjk, 1.0, "CJK 必须按全角估算")
	require.Greater(t, cjk, 1.5*measureTextWidth("a"), "全角字形应明显宽于半角字母")

	long := strings.Repeat("例", 30) + ":443"
	require.Greater(t, measureTextWidth(long), maxLabelWidth,
		"用例前提：这个 IDN 超出显示上限")
	require.True(t, strings.HasSuffix(truncateToWidth(long, maxLabelWidth, "…"), "…"),
		"超长 IDN 也要触发截断")
}

// TestTruncateToWidthKeepsEllipsis 超长文本截断后必须带省略号，且宽度不再超限。
func TestTruncateToWidthKeepsEllipsis(t *testing.T) {
	t.Parallel()

	addr := "a.very.long.hostname.for.a.branch.office.example.com:443"
	got := truncateToWidth(addr, maxLabelWidth, "…")
	require.True(t, strings.HasSuffix(got, "…"), "截断结果需要省略号: %q", got)
	require.LessOrEqual(t, measureTextWidth(got), maxLabelWidth)
	require.True(t, strings.HasPrefix(addr, strings.TrimSuffix(got, "…")), "必须保留地址前缀: %q", got)
	require.Equal(t, "short.example:443", truncateToWidth("short.example:443", maxLabelWidth, "…"))
}
