//go:build windows && amd64

package assets

import _ "embed"

//go:embed wintun/wintun_amd64.dll
var WintunDLL []byte
