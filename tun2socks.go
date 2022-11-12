package easyss

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"github.com/nange/easyss/util"
	log "github.com/sirupsen/logrus"
	"github.com/xjasonlyu/tun2socks/v2/engine"
)

//TODO: 1. wintun.dll embed done! 2. bat内部参数通过传入方式  3. 全局代理，不弹黑窗出来

var (
	//go:embed scripts/create_tun_dev.sh
	createTunDevSh []byte
	//go:embed scripts/create_tun_dev_windows.bat
	createTunDevShWindows []byte
	//go:embed scripts/close_tun_dev.sh
	closeTunDevSh []byte
	//go:embed scripts/close_tun_dev_windows.bat
	closeTunDevShWindows []byte

	//go:embed wintun/wintun_amd64.dll
	wintunAmd64 []byte
	//go:embed wintun/wintun_arm64.dll
	wintunArm64 []byte
	//go:embed wintun/wintun_x86.dll
	wintunX86 []byte
	//go:embed wintun/wintun_arm.dll
	wintunArm []byte
)

const TunDevice = "tun-easyss"

func (ss *Easyss) CreateTun2socks() error {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	if err := writeWinTunToDiskIfNeeded(); err != nil {
		log.Errorf("write wintun.dll to disk err:%s", err.Error())
		return err
	}

	key := &engine.Key{
		Proxy:                ss.Socks5ProxyAddr(),
		Device:               TunDevice,
		LogLevel:             "error",
		TCPSendBufferSize:    "1m",
		TCPReceiveBufferSize: "1m",
		UDPTimeout:           ss.Timeout(),
	}
	engine.Insert(key)
	engine.Start()

	if err := ss.createTunDevAndSetIpRoute(); err != nil {
		log.Errorf("add tun device and set ip-route err:%s", err.Error())
		return err
	}

	ss.tun2socksEnabled = true
	log.Infof("tun2socks server and tun device init success")
	return nil
}

func (ss *Easyss) createTunDevAndSetIpRoute() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if ss.ServerIP() == "" {
		return errors.New("server ips is empty")
	}

	var shellFilename string
	var shellContent []byte
	switch runtime.GOOS {
	case "linux":
		shellFilename = "create_tun_dev.sh"
		shellContent = createTunDevSh
	case "windows":
		shellFilename = "create_tun_dev_windows.bat"
		shellContent = createTunDevShWindows
	default:
		return fmt.Errorf("unsupported os:%s", runtime.GOOS)
	}

	namePath, err := util.WriteToTemp(shellFilename, shellContent)
	if err != nil {
		log.Errorf("write close_tun_dev.sh to temp file err:%v", err.Error())
		return err
	}
	defer os.RemoveAll(namePath)

	switch runtime.GOOS {
	case "linux":
		if err := exec.CommandContext(ctx, "pkexec", "bash",
			namePath, TunDevice, ss.ServerIP(), ss.LocalGateway(), ss.LocalDevice()).Run(); err != nil {
			log.Errorf("exec %s err:%s", shellFilename, err.Error())
			return err
		}
	case "windows":
		dir := filepath.Dir(namePath)
		newNamePath := filepath.Join(dir, shellFilename)
		if err := os.Rename(namePath, newNamePath); err != nil {
			return err
		}
		namePath = newNamePath
		if err := exec.CommandContext(ctx, "cmd.exe", "/C",
			namePath, TunDevice, ss.ServerIP(), ss.LocalGateway()).Run(); err != nil {
			log.Errorf("exec %s err:%s", shellFilename, err.Error())
			return err
		}
	default:
		return fmt.Errorf("unsupported os:%s", runtime.GOOS)
	}

	return nil
}

func (ss *Easyss) CloseTun2socks() error {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	return ss.closeTun2socks()
}

func (ss *Easyss) closeTun2socks() error {
	engine.Stop()
	if err := ss.closeTunDevAndDelIpRoute(); err != nil {
		return err
	}

	ss.tun2socksEnabled = false
	return nil
}

func (ss *Easyss) closeTunDevAndDelIpRoute() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var shellFilename string
	var shellContent []byte
	switch runtime.GOOS {
	case "linux":
		shellFilename = "close_tun_dev.sh"
		shellContent = closeTunDevSh
	case "windows":
		shellFilename = "close_tun_dev_windows.bat"
		shellContent = closeTunDevShWindows
	default:
		return fmt.Errorf("unsupported os:%s", runtime.GOOS)
	}

	namePath, err := util.WriteToTemp(shellFilename, shellContent)
	if err != nil {
		log.Errorf("write close_tun_dev.sh to temp file err:%v", err.Error())
		return err
	}
	defer os.RemoveAll(namePath)

	switch runtime.GOOS {
	case "linux":
		if err := exec.CommandContext(ctx, "pkexec", "bash",
			namePath, TunDevice, ss.ServerIP(), ss.LocalGateway(), ss.LocalDevice()).Run(); err != nil {
			log.Errorf("exec %s err:%s", shellFilename, err.Error())
			return err
		}
	case "windows":
		dir := filepath.Dir(namePath)
		newNamePath := filepath.Join(dir, shellFilename)
		if err := os.Rename(namePath, newNamePath); err != nil {
			return err
		}
		namePath = newNamePath
		if err := exec.CommandContext(ctx, "cmd.exe", "/C",
			namePath, ss.ServerIP(), ss.LocalGateway()).Run(); err != nil {
			log.Errorf("exec %s err:%s", shellFilename, err.Error())
			return err
		}
	default:
		return fmt.Errorf("unsupported os:%s", runtime.GOOS)
	}

	return nil
}

func writeWinTunToDiskIfNeeded() error {
	if runtime.GOOS != "windows" {
		return nil
	}

	writeBytes := func(b []byte) error {
		path := filepath.Join(util.CurrentDir(), "wintun.dll")
		return os.WriteFile(path, b, 0666)
	}

	switch runtime.GOARCH {
	case "amd64":
		return writeBytes(wintunAmd64)
	case "arm64":
		return writeBytes(wintunArm64)
	case "386":
		return writeBytes(wintunX86)
	case "arm":
		return writeBytes(wintunArm)
	default:
		return fmt.Errorf("unsupported arch:%s", runtime.GOARCH)
	}
}
