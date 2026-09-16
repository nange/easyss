package selfupdate

import (
	"fmt"
	"runtime"
)

// Product 标识正在更新的二进制变体。它同时决定 release 资产名和 release zip
// 内部的暂存二进制名，遵循 CI 命名规范（<product>-<goos>-<goarch>.zip）。
type Product string

const (
	// ProductClient 是带托盘客户端的构建（二进制 "easyss"/"easyss.exe"）。
	ProductClient Product = "easyss"
	// ProductHeadless 是无界面客户端的构建（二进制 "easyss-headless"）。
	ProductHeadless Product = "easyss-headless"
	// ProductServer 是服务端的构建（二进制 "easyss-server"/"easyss-server.exe"）。
	ProductServer Product = "easyss-server"
)

// assetName 返回产品在某个平台上的 release 资产名，例如
// ("easyss-server", "linux", "amd64") -> "easyss-server-linux-amd64.zip"。
func (p Product) assetName(goos, goarch string) string {
	return fmt.Sprintf("%s-%s-%s.zip", p, goos, goarch)
}

// binaryName 返回当前平台在 release zip 内部的暂存二进制名。
func (p Product) binaryName() string {
	name := string(p)
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return name
}
