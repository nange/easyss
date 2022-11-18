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
	"strings"
	"time"

	"github.com/nange/easyss/util"
	log "github.com/sirupsen/logrus"
	"github.com/xjasonlyu/tun2socks/v2/engine"
)

var (
	//go:embed scripts/create_tun_dev.sh
	createTunDevSh []byte
	//go:embed scripts/create_tun_dev_windows.bat
	createTunDevShWindows []byte
	//go:embed scripts/create_tun_dev_darwin.sh
	createTunDevShDarwin []byte
	//go:embed scripts/close_tun_dev.sh
	closeTunDevSh []byte
	//go:embed scripts/close_tun_dev_windows.bat
	closeTunDevShWindows []byte
	//go:embed scripts/close_tun_dev_darwin.sh
	closeTunDevShDarwin []byte

	//go:embed wintun/wintun_amd64.dll
	wintunAmd64 []byte
	//go:embed wintun/wintun_arm64.dll
	wintunArm64 []byte
	//go:embed wintun/wintun_x86.dll
	wintunX86 []byte
	//go:embed wintun/wintun_arm.dll
	wintunArm []byte
)

const (
	TunDevice       = "tun-easyss"
	TunDeviceDarwin = "utun9"
	TunIP           = "198.18.0.1"
	TunGW           = "198.18.0.1"
	TunMask         = "255.255.0.0"
	TunIPSub        = "198.18.0.1/16"
)

var (
	_TunDevice string

	_createTunFilename string
	_createTunBytes    []byte

	_closeTunFilename string
	_closeTunBytes    []byte
)

type Tun2socksStatus int

const (
	Tun2socksStatusOff Tun2socksStatus = iota
	Tun2socksStatusAuto
	Tun2socksStatusOn
)

func init() {
	_TunDevice = TunDevice

	switch runtime.GOOS {
	case "linux":
		_createTunFilename = "create_tun_dev.sh"
		_createTunBytes = createTunDevSh

		_closeTunFilename = "close_tun_dev.sh"
		_closeTunBytes = closeTunDevSh
	case "windows":
		_createTunFilename = "create_tun_dev_windows.bat"
		_createTunBytes = createTunDevShWindows

		_closeTunFilename = "close_tun_dev_windows.bat"
		_closeTunBytes = closeTunDevShWindows
	case "darwin":
		_TunDevice = TunDeviceDarwin

		_createTunFilename = "create_tun_dev_darwin.sh"
		_createTunBytes = createTunDevShDarwin

		_closeTunFilename = "close_tun_dev_darwin.sh"
		_closeTunBytes = closeTunDevShDarwin
	default:
		log.Infof("unsupported os:%s, tun2socks service can't be enabled", runtime.GOOS)
	}
}

func (ss *Easyss) CreateTun2socks(status Tun2socksStatus) error {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	if ss.tun2socksStatus != Tun2socksStatusOff {
		ss.tun2socksStatus = status
		return nil
	}

	switch runtime.GOOS {
	case "linux":
		if err := ss.createTunDevAndSetIpRoute(); err != nil {
			log.Errorf("add tun device and set ip-route err:%s", err.Error())
			return err
		}
		ss.startTun2socksEngine()
	case "darwin":
		ss.startTun2socksEngine()
		if err := ss.createTunDevAndSetIpRoute(); err != nil {
			log.Errorf("add tun device and set ip-route err:%s", err.Error())
			return err
		}
	case "windows":
		if err := writeWinTunToDisk(); err != nil {
			log.Errorf("write wintun.dll to disk err:%s", err.Error())
			return err
		}
		ss.startTun2socksEngine()
		if err := ss.createTunDevAndSetIpRoute(); err != nil {
			log.Errorf("add tun device and set ip-route err:%s", err.Error())
			return err
		}
	default:
		return fmt.Errorf("unsupported os:%s", runtime.GOOS)
	}

	ss.tun2socksStatus = status
	log.Infof("tun2socks server and tun device create successfully")
	return nil
}

func (ss *Easyss) startTun2socksEngine() {
	key := &engine.Key{
		Proxy:                ss.Socks5ProxyAddr(),
		Device:               _TunDevice,
		LogLevel:             "error",
		TCPSendBufferSize:    "128kb",
		TCPReceiveBufferSize: "128kb",
		UDPTimeout:           ss.Timeout(),
	}
	engine.Insert(key)
	engine.Start()
}

func (ss *Easyss) createTunDevAndSetIpRoute() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if ss.ServerIP() == "" {
		return errors.New("server ips is empty")
	}

	namePath, err := util.WriteToTemp(_createTunFilename, _createTunBytes)
	if err != nil {
		log.Errorf("write close_tun_dev.sh to temp file err:%v", err.Error())
		return err
	}
	defer os.RemoveAll(namePath)

	switch runtime.GOOS {
	case "linux":
		if err := exec.CommandContext(ctx, "pkexec", "bash",
			namePath, _TunDevice, TunIPSub, TunGW, ss.ServerIP(), ss.LocalGateway(), ss.LocalDevice()).Run(); err != nil {
			log.Errorf("exec %s err:%s", _createTunFilename, err.Error())
			return err
		}
	case "windows":
		dir := filepath.Dir(namePath)
		newNamePath := filepath.Join(dir, _createTunFilename)
		if err := os.Rename(namePath, newNamePath); err != nil {
			return err
		}
		namePath = newNamePath
		if err := exec.CommandContext(ctx, "cmd.exe", "/C",
			namePath, _TunDevice, TunIP, TunGW, TunMask, ss.ServerIP(), ss.LocalGateway()).Run(); err != nil {
			log.Errorf("exec %s err:%s", _createTunFilename, err.Error())
			return err
		}
	case "darwin":
		if err := exec.CommandContext(ctx, "osascript", "-e",
			fmt.Sprintf("do shell script \"sh %s %s %s %s %s %s\" with administrator privileges",
				namePath, _TunDevice, TunIP, TunGW, ss.ServerIP(), ss.LocalGateway())).Run(); err != nil {
			log.Errorf("exec %s err:%s", _createTunFilename, err.Error())
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

	if ss.tun2socksStatus == Tun2socksStatusOff {
		return nil
	}
	return ss.closeTun2socks()
}

func (ss *Easyss) closeTun2socks() error {
	engine.Stop()
	if err := ss.closeTunDevAndDelIpRoute(); err != nil {
		if strings.Contains(err.Error(), "exit status 126") {
			// canceled on linux, restart engine
			engine.Start()
			return nil
		}
	}

	ss.tun2socksStatus = Tun2socksStatusOff
	log.Infof("tun2socks server and tun device close successfully")
	return nil
}

func (ss *Easyss) closeTunDevAndDelIpRoute() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	namePath, err := util.WriteToTemp(_closeTunFilename, _closeTunBytes)
	if err != nil {
		log.Errorf("write close_tun_dev.sh to temp file err:%v", err.Error())
		return err
	}
	defer os.RemoveAll(namePath)

	switch runtime.GOOS {
	case "linux":
		if err := exec.CommandContext(ctx, "pkexec", "bash",
			namePath, _TunDevice, ss.ServerIP(), ss.LocalGateway(), ss.LocalDevice()).Run(); err != nil {
			log.Errorf("exec %s err:%s", _closeTunFilename, err.Error())
			return err
		}
	case "windows":
		dir := filepath.Dir(namePath)
		newNamePath := filepath.Join(dir, _closeTunFilename)
		if err := os.Rename(namePath, newNamePath); err != nil {
			return err
		}
		namePath = newNamePath
		if err := exec.CommandContext(ctx, "cmd.exe", "/C",
			namePath, TunGW, ss.ServerIP(), ss.LocalGateway()).Run(); err != nil {
			log.Errorf("exec %s err:%s", _closeTunFilename, err.Error())
			return err
		}
	case "darwin":
		if err := exec.CommandContext(ctx, "osascript", "-e",
			fmt.Sprintf("do shell script \"sh %s %s %s %s\" with administrator privileges",
				namePath, TunGW, ss.ServerIP(), ss.LocalGateway())).Run(); err != nil {
			log.Errorf("exec %s err:%s", _closeTunFilename, err.Error())
			return err
		}
	default:
		return fmt.Errorf("unsupported os:%s", runtime.GOOS)
	}

	return nil
}

func writeWinTunToDisk() error {
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