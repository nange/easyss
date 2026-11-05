//go:build !headless && windows

package tray

// metricsColumn 在 Windows 上不参与布局：Win32 菜单把 "\t" 之后的内容右对齐到加速键列，
// 列位置由系统按同一菜单里最宽的标签排，不需要也不该由标题自己计算。
func metricsColumn([]string) float64 { return 0 }

// metricsSep 分隔 RTT 与下载速度：Win32 把整串指标右对齐到加速键列，间隔可以宽一点。
const metricsSep = "  "

// speedLabel 是下载速度在菜单里的写法。
func speedLabel(human string) string { return "↓" + human }

// alignMetrics 把指标放进 Win32 的加速键列：系统右对齐指标，标签与指标之间的间隔由系统
// 按最宽的标签给足，菜单右端也不会因为补空格多出一段空白。
func alignMetrics(label, metrics string, _ float64) string {
	return truncateLabel(label) + "\t" + metrics
}
