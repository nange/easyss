package selfupdate

import (
	"fmt"
	"runtime"
)

// Product identifies which binary variant is being updated. It drives both
// the release asset name and the staged binary name inside the release zip,
// following the CI naming scheme (<product>-<goos>-<goarch>.zip).
type Product string

const (
	// ProductClient is the tray client build (binary "easyss"/"easyss.exe").
	ProductClient Product = "easyss"
	// ProductHeadless is the headless client build (binary "easyss-headless").
	ProductHeadless Product = "easyss-headless"
	// ProductServer is the server build (binary "easyss-server"/"easyss-server.exe").
	ProductServer Product = "easyss-server"
)

// assetName returns the release asset name for the product on a platform,
// e.g. ("easyss-server", "linux", "amd64") -> "easyss-server-linux-amd64.zip".
func (p Product) assetName(goos, goarch string) string {
	return fmt.Sprintf("%s-%s-%s.zip", p, goos, goarch)
}

// binaryName returns the staged binary name inside the release zip for the
// current platform.
func (p Product) binaryName() string {
	name := string(p)
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return name
}
