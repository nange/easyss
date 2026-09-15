package tun

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	sharedconfig "github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/scripts"
	"github.com/nange/easyss/v3/util"
	"github.com/xjasonlyu/tun2socks/v2/engine"
)

const (
	tunTCPSendBufferSize    = "1MB"
	tunTCPReceiveBufferSize = "256KB"
)

// hooks are the points tests replace to exercise the Start() failure path
// without a TUN device, administrator rights or a live tun2socks engine: the
// platform scripts and the DNS setup can only be run for real as root and
// rewrite the network configuration of the machine running the test. Every
// hook defaults to the production implementation, and they are only ever
// written by tests (t.Cleanup restores them), never at runtime.
var (
	// createTunDevFn writes and runs the platform create script.
	createTunDevFn = func(m *Manager) error { return m.createTunDevAndSetIPRoute() }
	// closeTunDevFn writes and runs the platform close script. It backs both
	// the Stop() cleanup and the Start() rollback.
	closeTunDevFn = func(m *Manager) error { return m.closeTunDevAndDelIPRoute() }
	// saveAndSetDNSStepFn saves the original system DNS and switches the
	// system over to the TUN resolver (darwin/linux only).
	saveAndSetDNSStepFn = func(m *Manager) error { return m.saveAndSetDNSStep() }
	// restoreDNSStepFn puts the saved system DNS back.
	restoreDNSStepFn = func(m *Manager) error { return m.restoreDNSStep() }
	// engineStartFn starts the tun2socks engine; engineStopFn stops it.
	engineStartFn = func() error { return engine.Start() }
	engineStopFn  = func(reason string) { stopEngine(reason) }
	// settleDelay is the pause after the engine start that lets the device
	// come up before the platform script configures it.
	settleDelay = func() { time.Sleep(500 * time.Millisecond) }
)

type Config struct {
	Socks5Addr       string
	Device           string
	DeviceFD         int  // if > 0, use fd:// scheme instead of creating device by name; 0 means create by name
	SkipRouteCleanup bool // darwin: helper handles route/DNS cleanup, main process skips it in Stop()
	MTU              int
	Interface        string
	UDPTimeout       time.Duration
	LogLevel         string
	TunIP            string
	TunGW            string
	TunMask          string
	TunIPV6Sub       string
	TunGWV6          string
	ServerIPV6       string
	LocalGateway     string
	LocalGatewayV6   string
	DNSServer        string // DNS server to set during TUN mode (darwin only)
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
	cfg        Config
	dev        DeviceConfig
	running    bool
	originDNS  []string // original system DNS before TUN starts (darwin/linux only)
	dnsChanged bool     // saveAndSetDNSStep actually reconfigured the system DNS
	icmpH      *ICMPHandler

	ctx    context.Context    // cancels an in-progress Start()
	cancel context.CancelFunc // stored so Stop() can cancel the Start() goroutine
	done   chan struct{}      // closed when Start() finishes (success or failure)
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
			cfg.Device = sharedconfig.DefaultTunDeviceNameDarwin
		} else {
			cfg.Device = sharedconfig.DefaultTunDeviceName
		}
	}
	if cfg.Interface == "" || cfg.LocalGateway == "" {
		gw, dev, err := util.SysGatewayAndDevice()
		if err == nil {
			// Skip the easyss TUN device: when TUN routes are left over from
			// a previous session the route probe can resolve to it, and the
			// create script would then route the local gateway through the
			// TUN device itself.
			if iface, ierr := net.InterfaceByName(dev); ierr == nil && util.IsTunIface(iface) {
				log.Warn("[TUN] route probe resolved to easyss TUN device, skipping", "iface", dev)
				dev = ""
				gw = ""
			}
			if dev != "" {
				if cfg.Interface == "" {
					cfg.Interface = dev
				}
				if cfg.LocalGateway == "" {
					cfg.LocalGateway = gw
				}
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
		cfg.TunIPV6Sub = "2001:0db8:0:f101::1/64"
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

// manageSystemDNS reports whether this platform switches the system DNS over to
// the TUN resolver for the duration of a TUN session. Windows does not: its
// create/close scripts configure the adapter DNS themselves.
func manageSystemDNS() bool {
	return runtime.GOOS == "darwin" || runtime.GOOS == "linux"
}

func (m *Manager) Start() error {
	if scripts.CreateTunBytes == nil || scripts.CloseTunBytes == nil {
		return fmt.Errorf("tun: unsupported os %s", runtime.GOOS)
	}

	m.ctx, m.cancel = context.WithCancel(context.Background())
	m.done = make(chan struct{})
	defer close(m.done)

	// Fast-path: already cancelled before we begin.
	select {
	case <-m.ctx.Done():
		return m.ctx.Err()
	default:
	}

	if m.icmpH != nil {
		engine.SetICMPHandler(m.icmpH)
	}

	fdMode := m.cfg.DeviceFD > 0
	device := m.cfg.Device
	if fdMode {
		device = "fd://" + strconv.Itoa(m.cfg.DeviceFD)
	}

	if err := ensureWintun(); err != nil {
		return fmt.Errorf("tun: extract wintun.dll: %w", err)
	}

	key := &engine.Key{
		MTU:                      m.cfg.MTU,
		Device:                   device,
		LogLevel:                 m.cfg.LogLevel,
		UDPTimeout:               m.cfg.UDPTimeout,
		Proxy:                    m.cfg.Socks5Addr,
		TCPModerateReceiveBuffer: true,
		TCPSendBufferSize:        tunTCPSendBufferSize,
		TCPReceiveBufferSize:     tunTCPReceiveBufferSize,
	}

	engine.Insert(key)

	// Upstream turned Start into an error return instead of a log.Fatalf
	// (tun2socks #550/#552): report the failure to the caller rather than
	// exiting the process, and release the TUN device Start may have opened
	// before core.CreateStack failed.
	if err := engineStartFn(); err != nil {
		engineStopFn("start failed")
		return fmt.Errorf("tun: start engine: %w", err)
	}

	// Allow Stop() to cancel us before we touch routes / DNS.
	select {
	case <-m.ctx.Done():
		engineStopFn("start cancelled")
		return m.ctx.Err()
	default:
	}

	settleDelay()

	if !fdMode {
		// Save original DNS and set TUN DNS on darwin and linux.
		if manageSystemDNS() {
			if err := saveAndSetDNSStepFn(m); err != nil {
				log.Warn("[TUN] set system dns", "err", err)
			}
		}

		if err := createTunDevFn(m); err != nil {
			engineStopFn("create device failed")
			// The platform script can fail halfway through (it installs the
			// address first and the routes after), and the routes it already
			// added stay in the system routing table when only the engine is
			// stopped: Stop() below returns early because m.running is still
			// false, so nothing else ever removes them. Left behind, they send
			// traffic into a TUN device nothing reads from, which looks like a
			// dead network. Deleting them is idempotent and only meaningful on
			// the paths that just ran the create script.
			if closeErr := closeTunDevFn(m); closeErr != nil {
				log.Warn("[TUN] rollback routes after create failure", "err", closeErr)
			}
			// The system DNS was switched to the TUN resolver before the
			// device existed. Stop() returns early while m.running is false, so
			// the failure path has to put it back itself: left pointing at a
			// TUN device nothing answers on (or at a public resolver that is
			// only reachable through the tunnel), resolution dies system-wide
			// even though the proxy core keeps running.
			if manageSystemDNS() {
				if dnsErr := restoreDNSStepFn(m); dnsErr != nil {
					log.Warn("[TUN] rollback system dns after create failure", "err", dnsErr)
				}
			}
			return fmt.Errorf("tun: create device: %w", err)
		}
	}

	// Final check: if Stop() cancelled us while the platform script was
	// running, undo everything we just set up.
	select {
	case <-m.ctx.Done():
		engineStopFn("start cancelled")
		if !fdMode {
			_ = closeTunDevFn(m)
		}
		if manageSystemDNS() {
			_ = restoreDNSStepFn(m)
		}
		return m.ctx.Err()
	default:
	}

	m.running = true
	log.Info("[TUN] tun2socks started", "device", device, "proxy", m.cfg.Socks5Addr)
	return nil
}

func (m *Manager) Stop() {
	// If Start() is still in progress, cancel it and wait for it to
	// finish cleaning up before we proceed.
	if m.cancel != nil {
		m.cancel()
		log.Info("[TUN] Stop: waiting for Start goroutine to finish")
		<-m.done
		log.Info("[TUN] Stop: Start goroutine done")
	}

	if !m.running {
		log.Info("[TUN] Stop: not running, returning")
		return
	}

	log.Info("[TUN] Stop: calling engine.Stop")
	engineStopFn("stop")
	log.Info("[TUN] Stop: engine.Stop done")

	if !m.cfg.SkipRouteCleanup {
		_ = closeTunDevFn(m)

		// Restore original DNS on darwin and linux.
		if manageSystemDNS() {
			if err := restoreDNSStepFn(m); err != nil {
				log.Warn("[TUN] restore system dns", "err", err)
			}
		}
	}

	m.running = false
	log.Info("[TUN] tun2socks stopped")
}

// stopEngine stops the tun2socks engine, logging the error instead of
// propagating it: every caller sits on a cleanup path where a failed stop
// must not mask the original error, and upstream's StopOrFatal would exit the
// process. Stop is safe after a failed Start: it only releases the device and
// stack that were actually created.
func stopEngine(reason string) {
	if err := engine.Stop(); err != nil {
		log.Warn("[TUN] engine stop", "reason", reason, "err", err)
	}
}

func (m *Manager) IsRunning() bool {
	return m.running
}

// SetICMPHandler stores the ICMP handler and registers it with the engine.
// Safe to call before or after Start(); idempotent.
func (m *Manager) SetICMPHandler(h *ICMPHandler) {
	m.icmpH = h
	engine.SetICMPHandler(h)
}

// DeviceConfig returns the device configuration with platform defaults filled in.
func (m *Manager) DeviceConfig() DeviceConfig {
	return m.dev
}

func (m *Manager) createTunDevAndSetIPRoute() error {
	if scripts.CreateTunBytes == nil {
		return fmt.Errorf("tun: no create script for %s", runtime.GOOS)
	}

	ctx, cancel := context.WithTimeout(m.ctx, 60*time.Second)
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
		// The script reports failures with a non-zero exit code (see the
		// exit code contract in create_tun_dev_windows.bat); its output is
		// part of the returned error.
		if _, err := util.CommandContext(ctx, "cmd.exe", "/C", namePath, d.Device,
			d.TunIP, d.TunGW, d.TunMask, d.TunIPV6Sub, d.TunGWV6, d.ServerIPV6); err != nil {
			return fmt.Errorf("tun: exec create script: %w", err)
		}
	case "darwin":
		if os.Geteuid() == 0 {
			if _, err := util.CommandContext(ctx, "sh", namePath, d.Device, d.TunIP, d.TunGW, d.LocalGateway,
				d.TunIPV6Sub, d.TunGWV6, d.ServerIPV6, d.LocalGatewayV6); err != nil {
				return fmt.Errorf("tun: exec create script: %w", err)
			}
		} else {
			cmd := fmt.Sprintf("do shell script \"sh %s %s %s %s %s %s %s %s %s\" with administrator privileges",
				namePath, d.Device, d.TunIP, d.TunGW, d.LocalGateway,
				d.TunIPV6Sub, d.TunGWV6, d.ServerIPV6, d.LocalGatewayV6)
			if _, err := util.CommandContext(ctx, "osascript", "-e", cmd); err != nil {
				return fmt.Errorf("tun: exec create script: %w", err)
			}
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
		if _, err := util.CommandContext(ctx, cmdArgs[0], cmdArgs[1:]...); err != nil {
			log.Warn("[TUN] close script", "err", err)
		}
	case "windows":
		dir := filepath.Dir(namePath)
		newNamePath := filepath.Join(dir, scripts.CloseTunFilename)
		if err := os.Rename(namePath, newNamePath); err != nil {
			return fmt.Errorf("tun: rename close script: %w", err)
		}
		namePath = newNamePath
		// The third argument is the bare IPv6 address of the TUN device
		// (no /prefix): the script deletes the persistent v6 address, which
		// the create script's "add address" would refuse to duplicate.
		if _, err := util.CommandContext(ctx, "cmd.exe", "/C", namePath, d.Device, d.TunGW, bareV6Addr(d.TunIPV6Sub)); err != nil {
			log.Warn("[TUN] close script", "err", err)
		}
	case "darwin":
		// Mirror the helper's runCloseScript argument order:
		// device, tunGW, localGateway, tunGWV6, serverIPV6, localGatewayV6.
		if os.Geteuid() == 0 {
			if _, err := util.CommandContext(ctx, "sh", namePath, d.Device, d.TunGW, d.LocalGateway,
				d.TunGWV6, d.ServerIPV6, d.LocalGatewayV6); err != nil {
				log.Warn("[TUN] close script", "err", err)
			}
		} else {
			cmd := fmt.Sprintf("do shell script \"sh %s %s %s %s %s %s %s\" with administrator privileges",
				namePath, d.Device, d.TunGW, d.LocalGateway, d.TunGWV6, d.ServerIPV6, d.LocalGatewayV6)
			if _, err := util.CommandContext(ctx, "osascript", "-e", cmd); err != nil {
				log.Warn("[TUN] close script", "err", err)
			}
		}
	}
	return nil
}

// saveAndSetDNSStep saves the original system DNS and switches the system over
// to the TUN resolver. It records whether the system DNS was actually changed
// (dnsChanged), which is what restoreDNSStep and the Start() failure rollback
// act on: darwin leaves a hand-configured DNS alone, and restoring DNS that was
// never touched would clear it (see restoreDNSStep).
func (m *Manager) saveAndSetDNSStep() error {
	origin, err := util.SysDNS()
	if err != nil {
		return err
	}
	m.originDNS = origin
	m.dnsChanged = false

	if m.cfg.DNSServer == "" {
		return nil
	}

	var setErr error
	if runtime.GOOS == "linux" {
		// Linux also has to pin the resolver to the TUN device: a DNS
		// server configured for the physical link only is queried with
		// the socket bound to that link, so its lookups leave through the
		// physical NIC and bypass the tunnel (see util.SetSysDNSForTun).
		setErr = util.SetSysDNSForTun(m.dev.Device, []string{m.cfg.DNSServer})
	} else if len(origin) == 0 {
		// Darwin: only override DNS when the system has no custom DNS
		// configured (i.e. using DHCP-provided DNS). If the user has
		// manually set DNS, preserve their choice.
		setErr = util.SetSysDNS([]string{m.cfg.DNSServer})
	} else {
		// Darwin with a custom DNS: nothing was changed, so nothing has to
		// be restored, not even after a failed start.
		return nil
	}

	// The setup may have applied part of the change before reporting the
	// error, so the rollback has to run whenever it was attempted at all.
	m.dnsChanged = true
	return setErr
}

// restoreDNSStep undoes saveAndSetDNSStep. It is a no-op unless the system DNS
// was actually reconfigured: on darwin an untouched system would otherwise be
// written back as "empty", which clears the DHCP-provided servers.
func (m *Manager) restoreDNSStep() error {
	if !m.dnsChanged {
		return nil
	}

	if runtime.GOOS == "linux" {
		return util.RestoreSysDNSForTun(m.dev.Device, m.originDNS)
	}

	if len(m.originDNS) == 0 {
		return setSysDNSWithElevation([]string{"empty"})
	}

	curr, err := sysDNSWithElevation()
	if err != nil {
		return err
	}
	if !stringSliceEqual(m.originDNS, curr) {
		return setSysDNSWithElevation(m.originDNS)
	}
	return nil
}

// sysDNSWithElevation returns the current system DNS servers, using osascript
// elevation on darwin when not running as root.
func sysDNSWithElevation() ([]string, error) {
	if runtime.GOOS == "darwin" && os.Geteuid() != 0 {
		return util.SysDNSViaOSAScript()
	}
	return util.SysDNS()
}

// setSysDNSWithElevation sets the system DNS servers, using osascript
// elevation on darwin when not running as root.
func setSysDNSWithElevation(servers []string) error {
	if runtime.GOOS == "darwin" && os.Geteuid() != 0 {
		return util.SetSysDNSViaOSAScript(servers)
	}
	return util.SetSysDNS(servers)
}

func stringSliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}

func ipSub(ip, mask string) string {
	if ip == "" || mask == "" {
		return ""
	}
	return ip + "/" + mask
}

// bareV6Addr strips the prefix length from an "address/prefix" subnet string
// ("2001:db8::1/64" -> "2001:db8::1"): netsh add address takes the /prefix
// form, but the netsh delete address of the windows close script wants the
// plain address.
func bareV6Addr(sub string) string {
	addr, _, _ := strings.Cut(sub, "/")
	return addr
}
