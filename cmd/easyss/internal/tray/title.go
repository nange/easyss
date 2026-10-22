//go:build !headless

package tray

import (
	"fmt"
	"math"
	"strings"
	"unicode/utf16"
)

// 服务器菜单项"指标列"（RTT/下载速度）的对齐参数。不用 "\t" 分隔：AppKit 在未设 tab
// stop 时按 28pt 默认间隔把光标推到下一个倍数，间隔随地址长度在 0~28pt 之间乱跳。
const (
	// serverColumnWidth 是"指标列"的起始位置（pt），大于常见 IP 字面量宽度（"[2001:db8::1]:443"
	// ≈ 108pt）而小于常见域名（≈ 149pt）。
	serverColumnWidth = 168.0

	// minMetricsGap 是地址本身已超出 serverColumnWidth 时保证的最小间隔（pt）。
	minMetricsGap = 16.0

	// maxAddressWidth 是地址的显示上限（pt）：再长就截断加省略号，避免超长主机名把指标挤出菜单。
	maxAddressWidth = 200.0

	// columnStep 是地址超过 serverColumnWidth 之后指标列的量化步长：列位置取
	// serverColumnWidth + n*columnStep，让宽度相近的地址仍共用一列、互相对齐。
	columnStep = 16.0
)

// 填充用空格，从粗到细（都是菜单字体里宽度确定的空格字符，macOS 上不会缺字形）。
// 最细一级是 hair space（U+200A ≈ 0.84pt），列位置的残差因此不超过 0.5pt。
var titlePadSpaces = []string{"\u2003", "\u2002", " ", "\u200a"}

// formatTitle 生成选择服务器菜单项的标题：地址在左，指标从固定列开始，不依赖各平台对 "\t" 的展开规则。
func formatTitle(addr string, rttMs float64, downSpeed string) string {
	var metrics string
	if rttMs > 0 {
		metrics = fmt.Sprintf("%dms", int64(rttMs))
	}
	if downSpeed != "" {
		if metrics != "" {
			metrics += "  "
		}
		metrics += "↓" + downSpeed
	}
	if metrics == "" {
		return addr
	}
	return padToMetricsColumn(addr) + metrics
}

// padToMetricsColumn 把地址补到指标列，地址过长时先截断再补，指标列不会被推出菜单可见范围。
func padToMetricsColumn(addr string) string {
	addr = truncateToWidth(addr, maxAddressWidth, "…")
	width := measureTextWidth(addr)
	// metricsColumnStart 保证列位置至少比地址宽 minMetricsGap，这里的填充宽度恒 ≥ minMetricsGap。
	return addr + titlePad(metricsColumnStart(width)-width)
}

// metricsColumnStart 返回指标列的起始位置：默认是 serverColumnWidth；地址已贴到该列
// 时按 columnStep 量化右移。返回值恒 ≥ addrWidth+minMetricsGap。
func metricsColumnStart(addrWidth float64) float64 {
	minStart := addrWidth + minMetricsGap
	if minStart <= serverColumnWidth {
		return serverColumnWidth
	}
	steps := math.Ceil((minStart - serverColumnWidth) / columnStep)
	return serverColumnWidth + columnStep*steps
}

// truncateToWidth 把文本截到 maxWidth（pt）以内，超出时在末尾接省略号。
// 按 UTF-16 码元截断，与字符串 API 的单位保持一致。
func truncateToWidth(s string, maxWidth float64, ellipsis string) string {
	if measureTextWidth(s) <= maxWidth {
		return s
	}
	units := utf16.Encode([]rune(s))
	for n := len(units); n > 0; n-- {
		candidate := string(utf16.Decode(units[:n]))
		if measureTextWidth(candidate)+measureTextWidth(ellipsis) <= maxWidth {
			return candidate + ellipsis
		}
	}
	return ellipsis
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
