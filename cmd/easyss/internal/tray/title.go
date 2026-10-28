//go:build !headless

package tray

import (
	"fmt"
	"unicode/utf16"
)

const (
	// maxLabelWidth 是标签的显示上限（pt）：再长就截断加省略号，避免超长主机名或 name 把菜单撑出屏幕。
	maxLabelWidth = 200.0
)

// formatTitle 生成选择服务器菜单项的标题：标签（name 或地址）在左，指标从 column 列开始。
// 列按本菜单的标签算出（见 metricsColumn），不依赖固定列宽；Windows 上 column 不参与布局。
func formatTitle(label, metrics string, column float64) string {
	if metrics == "" {
		return label
	}
	return alignMetrics(label, metrics, column)
}

// metricsText 拼接选中项的指标：RTT 与下载速度，都没有时返回空串。
func metricsText(rttMs float64, downSpeed string) string {
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
	return metrics
}

// truncateLabel 截到显示上限；列宽、填充和菜单标题都基于同一份截断结果。
func truncateLabel(label string) string {
	return truncateToWidth(label, maxLabelWidth, "…")
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
