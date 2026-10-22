//go:build windows && arm64

package assets

import _ "embed"

//go:embed wintun/wintun_arm64.dll
var WintunDLL []byte
