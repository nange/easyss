package easyss

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/nange/easyss/v2/log"
	"github.com/nange/easyss/v2/util"
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

var (
	_createTunFilename string
	_createTunBytes    []byte

	_closeTunFilename string
	_closeTunBytes    []byte
)

type Tun2socksStatus int

const (
	Tun2socksStatusOff Tun2socksStatus = iota
	Tun2socksStatusOn
)

var T2SSTypeToString = map[Tun2socksStatus]string{
	Tun2socksStatusOff: "off",
	Tun2socksStatusOn:  "on",
}

var T2SSStringToType = map[string]Tun2socksStatus{
	"off": Tun2socksStatusOff,
	"on":  Tun2socksStatusOn,
}

func (t2ss Tun2socksStatus) String() string {
	if v, ok := T2SSTypeToString[t2ss]; ok {
		return v
	}
	return fmt.Sprintf("unknow Tun2socksStatus:%d", t2ss)
}

func init() {
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
		_createTunFilename = "create_tun_dev_darwin.sh"
		_createTunBytes = createTunDevShDarwin

		_closeTunFilename = "close_tun_dev_darwin.sh"
		_closeTunBytes = closeTunDevShDarwin
	default:
		log.Info("[TUN2SOCKS] unsupported os, tun2socks service can't be enabled", "os", runtime.GOOS)
	}
}

func (ss *Easyss) CreateTun2socks() error {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	if ss.enabledTun2socks {
		return nil
	}

	switch runtime.GOOS {
	case "linux":
		if err := ss.createTunDevAndSetIpRoute(); err != nil {
			log.Error("[TUN2SOCKS] add tun device and set ip-route", "err", err.Error())
			return err
		}
		ss.startTun2socksEngine()
	case "darwin":
		ss.startTun2socksEngine()
		if err := ss.setDNSIfEmpty(); err != nil {
			log.Error("[TUN2SOCKS] set system dns", "err", err)
			return err
		}
		if err := ss.createTunDevAndSetIpRoute(); err != nil {
			log.Error("[TUN2SOCKS] add tun device and set ip-route", "err", err)
			return err
		}
	case "windows":
		if err := writeWinTunToDisk(); err != nil {
			log.Error("[TUN2SOCKS] write wintun.dll to disk", "err", err)
			return err
		}
		ss.startTun2socksEngine()
		if err := ss.createTunDevAndSetIpRoute(); err != nil {
			log.Error("[TUN2SOCKS] add tun device and set ip-route", "err", err)
			return err
		}
	default:
		return fmt.Errorf("unsupported os:%s", runtime.GOOS)
	}

	ss.enabledTun2socks = true
	log.Info("[TUN2SOCKS] service and tun device create successfully")
	return nil
}

func (ss *Easyss) startTun2socksEngine() {
	key := &engine.Key{
		Proxy:                ss.Socks5ProxyAddr(),
		Device:               ss.TunConfig().TunDevice,
		LogLevel:             "error",
		TCPSendBufferSize:    RelayBufferSizeString,
		TCPReceiveBufferSize: RelayBufferSizeString,
		UDPTimeout:           ss.Timeout(),
	}
	engine.Insert(key)
	engine.Start()
}

func (ss *Easyss) createTunDevAndSetIpRoute() error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	if ss.ServerIP() == "" {
		return errors.New("server ips is empty")
	}

	namePath, err := util.WriteToTemp(_createTunFilename, _createTunBytes)
	if err != nil {
		log.Error("[TUN2SOCKS] write close_tun_dev.sh to temp file", "err", err)
		return err
	}
	defer os.RemoveAll(namePath)

	tc := ss.TunConfig()
	switch runtime.GOOS {
	case "linux":
		cmdArgs := []string{"pkexec", "bash", namePath, tc.TunDevice, tc.IPSub(), tc.TunGW, ss.ServerIP(), ss.LocalGateway(), ss.LocalDevice()}
		if os.Geteuid() == 0 {
			log.Info("[TUN2SOCKS] current user is root, use bash directly")
			cmdArgs = cmdArgs[1:]
		}
		if _, err := util.CommandContext(ctx, cmdArgs[0], cmdArgs[1:]...); err != nil {
			log.Error("[TUN2SOCKS] exec", "file", _createTunFilename, "err", err)
			return err
		}
	case "windows":
		dir := filepath.Dir(namePath)
		newNamePath := filepath.Join(dir, _createTunFilename)
		if err := os.Rename(namePath, newNamePath); err != nil {
			return err
		}
		namePath = newNamePath
		if _, err := util.CommandContext(ctx, "cmd.exe", "/C",
			namePath, tc.TunDevice, tc.TunIP, tc.TunGW, tc.TunMask, ss.ServerIP(), ss.LocalGateway()); err != nil {
			log.Error("[TUN2SOCKS] exec", "file", _createTunFilename, "err", err)
			return err
		}
	case "darwin":
		if _, err := util.CommandContext(ctx, "osascript", "-e",
			fmt.Sprintf("do shell script \"sh %s %s %s %s %s %s\" with administrator privileges",
				namePath, tc.TunDevice, tc.TunIP, tc.TunGW, ss.ServerIP(), ss.LocalGateway())); err != nil {
			log.Error("[TUN2SOCKS] exec", "file", _createTunFilename, "err", err)
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

	if !ss.enabledTun2socks {
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
	if err := ss.setDNSToOrigin(); err != nil {
		log.Error("[TUN2SOCKS] set system dns to origin", "err", err)
	}

	ss.enabledTun2socks = false
	log.Info("[TUN2SOCKS] service and tun device close successfully")
	return nil
}

func (ss *Easyss) closeTunDevAndDelIpRoute() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	namePath, err := util.WriteToTemp(_closeTunFilename, _closeTunBytes)
	if err != nil {
		log.Error("[TUN2SOCKS] write close_tun_dev.sh to temp file", "err", err)
		return err
	}
	defer os.RemoveAll(namePath)

	tc := ss.TunConfig()
	switch runtime.GOOS {
	case "linux":
		if _, err := util.CommandContext(ctx, "pkexec", "bash",
			namePath, tc.TunDevice, ss.ServerIP(), ss.LocalGateway(), ss.LocalDevice()); err != nil {
			log.Error("[TUN2SOCKS] exec", "file", _closeTunFilename, "err", err)
			return err
		}
	case "windows":
		dir := filepath.Dir(namePath)
		newNamePath := filepath.Join(dir, _closeTunFilename)
		if err := os.Rename(namePath, newNamePath); err != nil {
			return err
		}
		namePath = newNamePath
		if _, err := util.CommandContext(ctx, "cmd.exe", "/C",
			namePath, tc.TunGW, ss.ServerIP(), ss.LocalGateway()); err != nil {
			log.Error("[TUN2SOCKS] exec", "file", _closeTunFilename, "err", err)
			return err
		}
	case "darwin":
		if _, err := util.CommandContext(ctx, "osascript", "-e",
			fmt.Sprintf("do shell script \"sh %s %s %s %s\" with administrator privileges",
				namePath, tc.TunGW, ss.ServerIP(), ss.LocalGateway())); err != nil {
			log.Error("[TUN2SOCKS] exec", "file", _closeTunFilename, "err", err)
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
		if _, err := os.Stat(path); err == nil {
			// already exist the wintun.dll file
			return nil
		}
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

func (ss *Easyss) setDNSIfEmpty() error {
	if len(ss.originDNS) == 0 {
		ip, _, _ := net.SplitHostPort(ss.directDNSServer)
		return util.SetSysDNS([]string{ip})
	}
	return nil
}

func (ss *Easyss) setDNSToOrigin() error {
	curr, err := util.SysDNS()
	if err != nil {
		return err
	}
	if len(ss.originDNS) == 0 {
		return util.SetSysDNS([]string{"empty"})
	}

	equals := true
	for i, item := range ss.originDNS {
		if item != curr[i] {
			equals = false
			break
		}
	}
	if !equals {
		return util.SetSysDNS(ss.originDNS)
	}

	return nil
}
