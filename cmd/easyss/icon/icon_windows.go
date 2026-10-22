package icon

import (
	_ "embed"
)

// TrayData 是托盘图标所用的 PNG 数据（gogpu/systray 要求 PNG 格式）。
//
//go:embed icon_32_32.png
var TrayData []byte
