//go:build !headless

package main

import (
	"fmt"
	"math"
	"strings"
	"unicode/utf16"
)

// 选择服务器菜单项里"指标列"（RTT/下载速度）的对齐参数。
//
// 之前靠一个 "\t" 分隔地址与指标，但 AppKit 在没有显式 tab stop 时用的是
// 28pt 的默认 tab 间隔：tab 只把光标推到"下一个 28pt 倍数"，于是地址到指标的
// 视觉间隔 = 28 - (地址宽度 mod 28)，随地址长度在 0~28pt 之间乱跳
// （实测同一套 label 里 "1.2.3.4:443" 约 16pt、"203.0.113.9:443" 约 15pt、
// "cn2.example.net:443" 约 24pt）。IP 字面量比域名短、落点靠前，看起来就是
// 指标"贴着"地址；域名恰好落在 tab stop 附近，于是显得间隔很大。
//
// 这里改成自己算列位置（宽度用纯 Go 的 measureTextWidth，见 tray_title_measure.go）：
// 把地址用不同宽度的空格补到 serverColumnWidth，所有菜单项的指标都从同一列开始，
// 与地址是 IP 还是域名无关。
const (
	// serverColumnWidth 是选择服务器菜单里"指标列"的起始位置（单位 pt）。
	// 取值大于常见 IP 字面量的宽度（"203.0.113.9:443" ≈ 97pt、"[2001:db8::1]:443"
	// ≈ 108pt），又小于常见域名（"server.example.com:443" ≈ 149pt），
	// 这样两类地址都能留出足够宽、且彼此一致的间隔。
	serverColumnWidth = 168.0

	// minMetricsGap 是地址本身已超出 serverColumnWidth 时保证的最小间隔（单位 pt）。
	minMetricsGap = 16.0

	// maxAddressWidth 是地址的显示上限（单位 pt）：再长就截断并在末尾加省略号，
	// 既保证指标与地址之间留有可辨的间隔，也避免超长主机名把指标挤出菜单可见范围。
	maxAddressWidth = 200.0

	// columnStep 是"地址超过 serverColumnWidth 之后"指标列的量化步长：
	// 列位置取 serverColumnWidth + n*columnStep（n 取最小可行值），因此同一段宽度
	// 区间的地址仍然共用一列，不会出现只差两三个 pt 的相邻项互相对不齐。
	columnStep = 16.0
)

// 填充用空格，从粗到细（都是菜单字体里宽度确定的空格字符，macOS 上不会缺字形）。
// 最细一级是 hair space（U+200A ≈ 0.84pt），因此列位置的残差不会超过 0.5pt。
var titlePadSpaces = []string{"\u2003", "\u2002", " ", "\u200a"}

// formatTitle 生成选择服务器菜单项的标题：地址在左，指标（RTT/下载速度）从
// 固定列开始，不依赖各平台对 "\t" 的不同展开规则。
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

// padToMetricsColumn 把地址补到指标列。地址过长时先截断再补，保证指标列不会被
// 推到菜单可见范围之外。
func padToMetricsColumn(addr string) string {
	addr = truncateToWidth(addr, maxAddressWidth, "…")
	width := measureTextWidth(addr)

	target := serverColumnWidth
	if minStart := width + minMetricsGap; minStart > target {
		// 地址已经贴到目标列（或多长都留不出 minMetricsGap）时，按 columnStep
		// 量化列位置，让一批宽度相近的地址仍落在同一列上。
		target = serverColumnWidth + columnStep*math.Ceil((minStart-serverColumnWidth)/columnStep)
	}
	if remaining := target - width; remaining > 0 {
		return addr + titlePad(remaining)
	}
	return addr + " "
}

// truncateToWidth 把文本截到 maxWidth（单位 pt）以内，超出时在末尾接省略号。
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
// hair space 直接取最接近目标宽度的份数，再按"整体宽度离目标多远"选最优组合。
func titlePad(width float64) string {
	units := make([]float64, len(titlePadSpaces))
	for i, sp := range titlePadSpaces {
		units[i] = measureTextWidth(sp)
	}

	best := []int{}
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
	if len(best) == 0 {
		return ""
	}

	var b strings.Builder
	for i, count := range best {
		b.WriteString(strings.Repeat(titlePadSpaces[i], count))
	}
	return b.String()
}
