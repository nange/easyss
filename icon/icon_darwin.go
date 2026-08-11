package icon

import (
	_ "embed"
)

// TrayData is the PNG data used for the tray icon. The logo is scaled down
// to ~65% of the 44x44 canvas so it doesn't look oversized in the menu bar.
//
//go:embed icon_tray_darwin.png
var TrayData []byte
