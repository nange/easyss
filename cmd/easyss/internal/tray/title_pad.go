//go:build !headless && !windows

package tray

import "strings"

// 填充用空格，从粗到细（都是菜单字体里宽度确定的空格字符）。
// 最细一级是 hair space（U+200A ≈ 0.84pt），列位置的残差因此不超过 0.5pt。
var titlePadSpaces = []string{"\u2003", "\u2002", " ", "\u200a"}

// minMetricsGap 是菜单里最宽的标签与指标列之间保证的间隔（pt）。
const minMetricsGap = 16.0

// metricsColumn 返回本菜单指标列的起始位置：最宽标签加 minMetricsGap。列随标签实际宽度走，
// 短标签（配置了 name 的服务器）不会像固定列那样留下大段空白，所有标签仍共用一列。
func metricsColumn(labels []string) float64 {
	widest := 0.0
	for _, label := range labels {
		widest = max(widest, measureTextWidth(truncateLabel(label)))
	}
	return widest + minMetricsGap
}

// alignMetrics 用空格把标签补到指标列。AppKit 没有右对齐列：未设 tab stop 时 "\t" 落在
// 28pt 的默认间隔上，列位置随标签长度在 0~28pt 之间乱跳。
func alignMetrics(label, metrics string, column float64) string {
	label = truncateLabel(label)
	return label + titlePad(column-measureTextWidth(label)) + metrics
}

// titlePad 用 titlePadSpaces 凑出尽量接近 width 的填充：前三级枚举份数，最细的
// hair space 取最接近目标宽度的份数。没有任何组合更接近时返回空串。
func titlePad(width float64) string {
	units := make([]float64, len(titlePadSpaces))
	for i, sp := range titlePadSpaces {
		units[i] = measureTextWidth(sp)
	}

	best := make([]int, len(titlePadSpaces))
	bestDiff := width
	for i := 0; float64(i)*units[0] <= width+units[0]; i++ {
		widthI := float64(i) * units[0]
		for j := 0; widthI+float64(j)*units[1] <= width+units[1]; j++ {
			widthJ := widthI + float64(j)*units[1]
			for k := 0; widthJ+float64(k)*units[2] <= width+units[2]; k++ {
				widthK := widthJ + float64(k)*units[2]
				residual := width - widthK
				for _, l := range []int{int(residual / units[3]), int(residual/units[3] + 0.5)} {
					if l < 0 {
						continue
					}
					diff := width - (widthK + float64(l)*units[3])
					if diff < 0 {
						diff = -diff
					}
					if diff < bestDiff {
						bestDiff = diff
						best = []int{i, j, k, l}
					}
				}
			}
		}
	}

	var b strings.Builder
	for i, count := range best {
		b.WriteString(strings.Repeat(titlePadSpaces[i], count))
	}
	return b.String()
}
