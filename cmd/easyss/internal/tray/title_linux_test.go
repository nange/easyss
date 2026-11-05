//go:build !headless && linux

package tray

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestMetricsTextIsCompact 指标串在 Linux 上收紧：RTT 与速度之间一个空格、数值与单位之间不留空格。
func TestMetricsTextIsCompact(t *testing.T) {
	t.Parallel()

	require.Equal(t, "126ms ↓24B/s", metricsText(126, "24 B/s"))
	require.Equal(t, "126ms ↓11.8KB/s", metricsText(126, "11.8 KB/s"))
	require.Equal(t, "126ms", metricsText(126, ""))
	require.Equal(t, "↓24B/s", metricsText(0, "24 B/s"))
}

// TestFormatTitleUsesPlainGap 标题里不能出现 U+2000–U+200A 这类对齐用空格：面板多是等宽字体，
// 它们会拿到整整一个字符宽（U+200A 实测 6.6px），24 个就把指标顶到弹窗外面。
func TestFormatTitleUsesPlainGap(t *testing.T) {
	t.Parallel()

	title := formatTitle("HKDV", metricsText(126, "24 B/s"), 0)
	require.Equal(t, "HKDV"+metricsGap+"126ms ↓24B/s", title)
	for _, r := range title {
		require.False(t, r >= '\u2000' && r <= '\u200a', "标题里有对齐用空格 %U: %q", r, title)
	}
}

// TestFormatTitleAlwaysKeepsMetrics 放不下时也不裁指标：整串照发，由面板在行尾加省略号——
// 省略号本身就是"这行太长"的信号，比我们悄悄丢掉速度更好读。
func TestFormatTitleAlwaysKeepsMetrics(t *testing.T) {
	t.Parallel()

	labels := []string{
		"HKDV",
		"EasyOrcArm",
		"orcarm.myeasyss.net:443",
		"very.long.hostname.for.a.branch.office.example.com:443",
	}
	for _, label := range labels {
		metrics := metricsText(486, "11.8 KB/s")
		title := formatTitle(label, metrics, 0)
		require.True(t, strings.HasSuffix(title, metrics), "指标必须整串下发: %q", title)
	}
}

// TestMetricsColumnIsUnusedOnLinux 列位置要靠宿主字体的实测宽度，Linux 上没有可用的来源。
func TestMetricsColumnIsUnusedOnLinux(t *testing.T) {
	t.Parallel()

	require.Zero(t, metricsColumn([]string{"香港DV", "edge.example.co.jp:8443"}))
}
