//go:build !headless && !windows

package tray

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// titleWidthForTest 用与生产代码完全相同的度量函数测量整段文本的宽度（单位 pt），
// 用来断言"指标列落在同一列"这一视觉契约：填充与标签必须在同一坐标系里相加。
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
	// 必须测量整段前缀（而不是逐字符相加）：度量本身已经是逐字符累加，
	// 再拆开测只会重复引入同一份误差。
	return titleWidthForTest(title[:idx])
}

// TestFormatTitleAlignsMetricsColumn 固定这个问题本身：不管标签是 IP 字面量、域名还是
// 短名字，指标都要从同一列开始（不能用 "\t"：28pt 的默认 tab 间隔会让列宽随标签长度乱跳）。
func TestFormatTitleAlignsMetricsColumn(t *testing.T) {
	t.Parallel()

	labels := []string{
		"1.2.3.4:443",
		"203.0.113.9:443",
		"cn2.example.net:443",
		"server.example.com:443",
		"[2001:db8::1]:443",
		"edge.example.co.jp:8443",
		"香港节点",
	}
	column := metricsColumn(labels)

	for _, label := range labels {
		title := formatTitle(label, 60, "649 B/s", column)
		require.NotContains(t, title, "\t", "不再依赖 tab 展开: %q", title)
		require.True(t, strings.HasPrefix(title, label), "标题必须以标签开头: %q", title)
		require.Contains(t, title, "↓649 B/s", "指标不能丢: %q", title)

		got := metricsColumnForTest(t, title)
		require.InDelta(t, column, got, 0.5, "标签 %q 的指标列偏移", label)
	}
}

// TestMetricsColumnFollowsWidestLabel 列宽跟着菜单里最宽的标签走：短名字不会再被固定列
// 推到很远的右边，指标与最宽标签之间只隔 minMetricsGap。
func TestMetricsColumnFollowsWidestLabel(t *testing.T) {
	t.Parallel()

	labels := []string{"香港DV", "香港华纳", "Oracle Arm", "香港狗云"}
	widest := 0.0
	for _, label := range labels {
		widest = max(widest, measureTextWidth(label))
	}

	column := metricsColumn(labels)
	require.InDelta(t, widest+minMetricsGap, column, 0.01, "列 = 最宽标签 + 最小间隔")

	for _, label := range labels {
		require.GreaterOrEqual(t, column-measureTextWidth(label), minMetricsGap-0.5,
			"标签 %q 与指标列的间隔不能小于最小值", label)
	}
}

// TestFormatTitleKeepsMinimalGapForWidestLabel 最宽的标签（列位置由它决定）与指标之间
// 也只能留 minMetricsGap 量级的间隔，不能因为填充算法出现大段空白。
func TestFormatTitleKeepsMinimalGapForWidestLabel(t *testing.T) {
	t.Parallel()

	labels := []string{"香港节点", "edge.example.co.jp:8443"}
	column := metricsColumn(labels)
	widest := labels[1]

	title := formatTitle(widest, 60, "649 B/s", column)
	gap := metricsColumnForTest(t, title) - titleWidthForTest(widest)
	require.GreaterOrEqual(t, gap, minMetricsGap-0.5, "不能小于最小间隔")
	require.LessOrEqual(t, gap, minMetricsGap+0.5, "最宽标签的间隔应正好是最小间隔")
}

// TestTitlePadNeverOvershoots 填充只允许为了更接近目标宽度而略微超过（最多半个
// 最细一级空格），不允许出现"把标签推过目标列"的粗放填充。
func TestTitlePadNeverOvershoots(t *testing.T) {
	t.Parallel()

	for _, target := range []float64{3, 7.5, 12.9, 30.2, 61.7, 120.4, 167.9} {
		pad := titlePad(target)
		width := titleWidthForTest(pad)
		require.LessOrEqual(t, width, target+0.75, "填充 %q 超出目标 %.1f", pad, target)
		require.Greater(t, width, target-0.5, "填充 %q 离目标 %.1f 太远", pad, target)
	}
}
