package icon

import (
	_ "embed"
)

// TrayData 是托盘图标所用的 PNG 数据。logo 被缩放到 44x44 画布的约 65%，
// 以免在菜单栏中显得过大。
//
//go:embed icon_tray_darwin.png
var TrayData []byte
