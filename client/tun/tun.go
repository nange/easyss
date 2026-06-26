package tun

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/scripts"
	"github.com/nange/easyss/v3/util"
	"github.com/xjasonlyu/tun2socks/v2/core/adapter"
	"github.com/xjasonlyu/tun2socks/v2/engine"
)

const (
	tunTCPSendBufferSize    = "1MB"
	tunTCPReceiveBufferSize = "256KB"
)

type Config struct {
	Socks5Addr     string
	Device         string
	MTU            int
	Interface      string
	UDPTimeout     time.Duration
	LogLevel       string
	TunIP          string
	TunGW          string
	TunMask        string
	TunIPV6Sub     string
	TunGWV6        string
	ServerIPV6     string
	LocalGateway   string
	LocalGatewayV6 string
}

type DeviceConfig struct {
	Device         string
	TunIP          string
	TunGW          string
	TunMask        string
	TunIPV6Sub     string
	TunGWV6        string
	ServerIPV6     string
	LocalGateway   string
	LocalGatewayV6 string
}

type Manager struct {
	cfg     Config
	dev     DeviceConfig
	running bool
}

func New(cfg Config) *Manager {
	if cfg.MTU <= 0 {
		cfg.MTU = 1500
	}
	if cfg.UDPTimeout <= 0 {
		cfg.UDPTimeout = 5 * time.Minute
	}
	if cfg.LogLevel == "" {
		cfg.LogLevel = "warn"
	}
	if cfg.Device == "" {
		if runtime.GOOS == "darwin" {
			cfg.Device = "utun9"
		} else {
			cfg.Device = "tun-easyss"
		}
	}
	if cfg.Interface == "" || cfg.LocalGateway == "" {
		gw, dev, err := util.SysGatewayAndDevice()
		if err == nil {
			if cfg.Interface == "" {
				cfg.Interface = dev
			}
			if cfg.LocalGateway == "" {
				cfg.LocalGateway = gw
			}
		} else {
			log.Warn("[TUN] detect default gateway/interface failed", "err", err)
		}
	}
	if cfg.LocalGatewayV6 == "" {
		gw, _, err := util.SysGatewayAndDeviceV6()
		if err == nil {
			cfg.LocalGatewayV6 = gw
		}
	}
	if cfg.TunIP == "" {
		cfg.TunIP = "198.18.0.1"
	}
	if cfg.TunGW == "" {
		cfg.TunGW = "198.18.0.1"
	}
	if cfg.TunMask == "" {
		cfg.TunMask = "255.255.0.0"
	}
	if cfg.TunIPV6Sub == "" {
		cfg.TunIPV6Sub = "2001:0db8:0:f101::1"
	}
	if cfg.TunGWV6 == "" {
		cfg.TunGWV6 = "fe80::30ff:1eff:feff:aaff"
	}

	return &Manager{
		cfg: cfg,
		dev: DeviceConfig{
			Device:         cfg.Device,
			TunIP:          cfg.TunIP,
			TunGW:          cfg.TunGW,
			TunMask:        cfg.TunMask,
			TunIPV6Sub:     cfg.TunIPV6Sub,
			TunGWV6:        cfg.TunGWV6,
			ServerIPV6:     cfg.ServerIPV6,
			LocalGateway:   cfg.LocalGateway,
			LocalGatewayV6: cfg.LocalGatewayV6,
		},
	}
}

func (m *Manager) Start(icmpH adapter.NetworkHandler) error {
	if scripts.CreateTunBytes == nil || scripts.CloseTunBytes == nil {
		return fmt.Errorf("tun: unsupported os %s", runtime.GOOS)
	}

	if icmpH != nil {
		engine.SetICMPHandler(icmpH)
	}

	key := &engine.Key{
		MTU:                      m.cfg.MTU,
		Device:                   m.cfg.Device,
		LogLevel:                 m.cfg.LogLevel,
		UDPTimeout:               m.cfg.UDPTimeout,
		Proxy:                    m.cfg.Socks5Addr,
		TCPModerateReceiveBuffer: true,
		TCPSendBufferSize:        tunTCPSendBufferSize,
		TCPReceiveBufferSize:     tunTCPReceiveBufferSize,
	}

	engine.Insert(key)
	engine.Start()

	time.Sleep(500 * time.Millisecond)

	if err := m.createTunDevAndSetIPRoute(); err != nil {
		engine.Stop()
		return fmt.Errorf("tun: create device: %w", err)
	}

	m.running = true
	log.Info("[TUN] tun2socks started", "device", m.cfg.Device, "proxy", m.cfg.Socks5Addr)
	return nil
}

func (m *Manager) Stop() {
	if !m.running {
		return
	}

	engine.Stop()

	_ = m.closeTunDevAndDelIPRoute()

	m.running = false
	log.Info("[TUN] tun2socks stopped")
}

func (m *Manager) IsRunning() bool {
	return m.running
}

func (m *Manager) createTunDevAndSetIPRoute() error {
	if scripts.CreateTunBytes == nil {
		return fmt.Errorf("tun: no create script for %s", runtime.GOOS)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	namePath, err := util.WriteToTemp(scripts.CreateTunFilename, scripts.CreateTunBytes)
	if err != nil {
		return fmt.Errorf("tun: write create script: %w", err)
	}
	defer os.RemoveAll(namePath) //nolint:errcheck

	d := m.dev

	switch runtime.GOOS {
	case "linux":
		cmdArgs := []string{"pkexec", "bash", namePath, d.Device,
			ipSub(d.TunIP, d.TunMask), d.TunGW, d.LocalGateway,
			d.TunIPV6Sub, d.TunGWV6, d.ServerIPV6, d.LocalGatewayV6}
		if os.Geteuid() == 0 {
			cmdArgs = cmdArgs[1:]
		}
		if _, err := util.CommandContext(ctx, cmdArgs[0], cmdArgs[1:]...); err != nil {
			return fmt.Errorf("tun: exec create script: %w", err)
		}
	case "windows":
		dir := filepath.Dir(namePath)
		newNamePath := filepath.Join(dir, scripts.CreateTunFilename)
		if err := os.Rename(namePath, newNamePath); err != nil {
			return fmt.Errorf("tun: rename script: %w", err)
		}
		namePath = newNamePath
		if _, err := util.CommandContext(ctx, "cmd.exe", "/C", namePath, d.Device,
			d.TunIP, d.TunGW, d.TunMask, d.TunIPV6Sub, d.TunGWV6, d.ServerIPV6); err != nil {
			return fmt.Errorf("tun: exec create script: %w", err)
		}
	case "darwin":
		cmd := fmt.Sprintf("do shell script \"sh %s %s %s %s %s %s %s %s %s\" with administrator privileges",
			namePath, d.Device, d.TunIP, d.TunGW, d.LocalGateway,
			d.TunIPV6Sub, d.TunGWV6, d.ServerIPV6, d.LocalGatewayV6)
		if _, err := util.CommandContext(ctx, "osascript", "-e", cmd); err != nil {
			return fmt.Errorf("tun: exec create script: %w", err)
		}
	}
	return nil
}

func (m *Manager) closeTunDevAndDelIPRoute() error {
	if scripts.CloseTunBytes == nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	namePath, err := util.WriteToTemp(scripts.CloseTunFilename, scripts.CloseTunBytes)
	if err != nil {
		return fmt.Errorf("tun: write close script: %w", err)
	}
	defer os.RemoveAll(namePath) //nolint:errcheck

	d := m.dev

	switch runtime.GOOS {
	case "linux":
		cmdArgs := []string{"pkexec", "bash", namePath, d.Device}
		if os.Geteuid() == 0 {
			cmdArgs = cmdArgs[1:]
		}
		_, _ = util.CommandContext(ctx, cmdArgs[0], cmdArgs[1:]...)
	case "windows":
		dir := filepath.Dir(namePath)
		newNamePath := filepath.Join(dir, scripts.CloseTunFilename)
		if err := os.Rename(namePath, newNamePath); err != nil {
			return fmt.Errorf("tun: rename close script: %w", err)
		}
		namePath = newNamePath
		_, _ = util.CommandContext(ctx, "cmd.exe", "/C", namePath, d.Device, d.TunGW)
	case "darwin":
		cmd := fmt.Sprintf("do shell script \"sh %s %s\" with administrator privileges",
			namePath, d.Device)
		_, _ = util.CommandContext(ctx, "osascript", "-e", cmd)
	}
	return nil
}

func ipSub(ip, mask string) string {
	if ip == "" || mask == "" {
		return ""
	}
	return ip + "/" + mask
}
