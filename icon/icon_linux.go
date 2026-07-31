package icon

import (
	_ "embed"
)

//go:embed icon_32_32.png
var Data []byte

// TrayData is the PNG data used for the tray icon.
//
//go:embed icon_32_32.png
var TrayData []byte
