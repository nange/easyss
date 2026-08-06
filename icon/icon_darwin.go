package icon

import (
	_ "embed"
)

// TrayData is the PNG data used for the tray icon.
//
//go:embed icon_256_256.png
var TrayData []byte
