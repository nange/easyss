package scripts

import (
	_ "embed"
	"runtime"
)

var (
	//go:embed create_tun_dev.sh
	CreateTunDevSh []byte
	//go:embed create_tun_dev_windows.bat
	CreateTunDevBat []byte
	//go:embed create_tun_dev_darwin.sh
	CreateTunDevDarwinSh []byte
	//go:embed close_tun_dev.sh
	CloseTunDevSh []byte
	//go:embed close_tun_dev_windows.bat
	CloseTunDevBat []byte
	//go:embed close_tun_dev_darwin.sh
	CloseTunDevDarwinSh []byte
)

var (
	CreateTunFilename string
	CreateTunBytes    []byte
	CloseTunFilename  string
	CloseTunBytes     []byte
)

func init() {
	switch runtime.GOOS {
	case "linux":
		CreateTunFilename = "create_tun_dev.sh"
		CreateTunBytes = CreateTunDevSh
		CloseTunFilename = "close_tun_dev.sh"
		CloseTunBytes = CloseTunDevSh
	case "windows":
		CreateTunFilename = "create_tun_dev_windows.bat"
		CreateTunBytes = CreateTunDevBat
		CloseTunFilename = "close_tun_dev_windows.bat"
		CloseTunBytes = CloseTunDevBat
	case "darwin":
		CreateTunFilename = "create_tun_dev_darwin.sh"
		CreateTunBytes = CreateTunDevDarwinSh
		CloseTunFilename = "close_tun_dev_darwin.sh"
		CloseTunBytes = CloseTunDevDarwinSh
	}
}
