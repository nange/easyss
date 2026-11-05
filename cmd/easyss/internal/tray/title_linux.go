//go:build !headless && linux

package tray

import "strings"

// 面板用自己的菜单字体原样渲染 label（dbusmenu 既没有列也没有 tab），所以这里不做 pt 级空格的
// 列对齐：U+200A 在等宽字体里会拿到整整一个字符宽，24 个就把指标顶出弹窗。指标只跟在固定间隔
// 后面，装不下就交给宿主截断——它在行尾补的省略号正好告诉用户这行太长了。

// metricsGap 是标签与指标之间的间隔。
const metricsGap = " "

// metricsColumn 不参与 Linux 布局：列位置要靠宿主字体的实测宽度，这里拿不到。
func metricsColumn([]string) float64 { return 0 }

// metricsSep 分隔 RTT 与下载速度：等宽字体里一个空格就是一整字符，收成一个。
const metricsSep = " "

// speedLabel 去掉数值与单位之间的空格（"11.8 KB/s" → "↓11.8KB/s"），少占一格。
func speedLabel(human string) string { return "↓" + strings.ReplaceAll(human, " ", "") }

// alignMetrics 只做拼接，不按可用宽度裁指标：面板装不下时自己加省略号，用户能一眼看出是行太长。
func alignMetrics(label, metrics string, _ float64) string {
	return truncateLabel(label) + metricsGap + metrics
}
