package icon

import (
	_ "embed"
)

// TrayData is the PNG data used for the tray icon (gogpu/systray requires PNG).
//
//go:embed icon_32_32.png
var TrayData []byte
