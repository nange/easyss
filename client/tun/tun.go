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

// hooks 是测试用来模拟 Start() 失败路径的替换点，无需 TUN 设备、管理员权限
// 或正在运行的 tun2socks engine：平台脚本和 DNS 设置只能以 root 身份真实运行，
// 并且会改写运行测试的机器的网络配置。每个 hook 默认指向生产实现，且只由测试
// 赋值（t.Cleanup 负责还原），运行时绝不会被改写。
var (
	// createTunDevFn 写入并运行平台的创建脚本。
	createTunDevFn = func(m *Manager) error { return m.createTunDevAndSetIPRoute() }
	// closeTunDevFn 写入并运行平台的关闭脚本。Stop() 的清理和 Start() 的回滚
	// 都由它承担。
	closeTunDevFn = func(m *Manager) error { return m.closeTunDevAndDelIPRoute() }
	// saveAndSetDNSStepFn 保存原始系统 DNS，并把系统切换到 TUN resolver
	// （仅 darwin/linux）。
	saveAndSetDNSStepFn = func(m *Manager) error { return m.saveAndSetDNSStep() }
	// restoreDNSStepFn 恢复已保存的系统 DNS。
	restoreDNSStepFn = func(m *Manager) error { return m.restoreDNSStep() }
	// engineStartFn 启动 tun2socks engine；engineStopFn 停止它。
	engineStartFn = func() error { return engine.Start() }
	engineStopFn  = func(reason string) { stopEngine(reason) }
	// settleDelay 是引擎启动后的停顿，让设备先就绪，随后平台脚本再配置它。
	settleDelay = func() { time.Sleep(500 * time.Millisecond) }
)

type Config struct {
	Socks5Addr       string
	Device           string
	DeviceFD         int  // 若 > 0，使用 fd:// scheme 打开设备而非按名称创建；0 表示按名称创建
	SkipRouteCleanup bool // darwin：helper 负责路由/DNS 清理，主进程在 Stop() 中跳过
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
	DNSServer        string // TUN 模式下要设置的 DNS 服务器（darwin/linux）
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
	originDNS  []string // TUN 启动前的原始系统 DNS（仅 darwin/linux）
	dnsChanged bool     // saveAndSetDNSStep 是否尝试过改动系统 DNS（即使中途失败也会置位，供回滚判断）
	icmpH      *ICMPHandler

	ctx    context.Context    // 用于取消进行中的 Start()
	cancel context.CancelFunc // 保存下来，供 Stop() 取消 Start() goroutine
	done   chan struct{}      // Start() 结束（成功或失败）时关闭
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
			// 跳过 easyss 自身的 TUN 设备：当上次会话残留 TUN 路由时，路由探测
			// 可能解析到它，创建脚本随后就会把本地网关路由进 TUN 设备本身。
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

// manageSystemDNS 报告当前平台是否在 TUN 会话期间把系统 DNS 切换到 TUN
// resolver。Windows 不会：它的创建/关闭脚本自己配置适配器 DNS。
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

	// 快速路径：还没开始就被取消了。
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

	// 上游把 Start 改成了返回错误而不是 log.Fatalf
	// （tun2socks #550/#552）：把失败报告给调用方而不是退出进程，
	// 并释放 Start 在 core.CreateStack 失败之前可能已打开的
	// TUN 设备。
	if err := engineStartFn(); err != nil {
		engineStopFn("start failed")
		return fmt.Errorf("tun: start engine: %w", err)
	}

	// 在改动路由 / DNS 之前，允许 Stop() 取消本次启动。
	select {
	case <-m.ctx.Done():
		engineStopFn("start cancelled")
		return m.ctx.Err()
	default:
	}

	settleDelay()

	if !fdMode {
		// 在 darwin 和 linux 上保存原始 DNS 并设置 TUN DNS。
		if manageSystemDNS() {
			if err := saveAndSetDNSStepFn(m); err != nil {
				log.Warn("[TUN] set system dns", "err", err)
			}
		}

		if err := createTunDevFn(m); err != nil {
			engineStopFn("create device failed")
			// 平台脚本可能在半途失败（它先安装地址，再安装路由），
			// 而只停止 engine 时，它已经添加的路由仍留在系统路由表里：
			// 下面的 Stop() 因为 m.running 还是 false 而提前返回，
			// 所以没有任何东西会再去移除它们。
			// 残留的路由会把流量送进一个无人读取的 TUN 设备，
			// 看起来就像网络死了。
			// 删除这些路由是幂等的，并且只在刚运行过创建脚本的
			// 路径上才有意义。
			if closeErr := closeTunDevFn(m); closeErr != nil {
				log.Warn("[TUN] rollback routes after create failure", "err", closeErr)
			}
			// 系统 DNS 在设备存在之前就已切换到 TUN resolver。
			// m.running 为 false 时 Stop() 会提前返回，
			// 所以失败路径必须自己把 DNS 恢复：
			// 若继续指向一个无人应答的 TUN 设备（或一个只能通过隧道
			// 访问的公共解析器），即使代理核心仍在运行，
			// 全系统的域名解析也会瘫痪。
			if manageSystemDNS() {
				if dnsErr := restoreDNSStepFn(m); dnsErr != nil {
					log.Warn("[TUN] rollback system dns after create failure", "err", dnsErr)
				}
			}
			return fmt.Errorf("tun: create device: %w", err)
		}
	}

	// 最后检查：如果平台脚本运行期间 Stop() 取消了本次启动，
	// 撤销刚才建立的一切。
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
	// 如果 Start() 仍在进行中，先取消它，
	// 等它完成清理后再继续。
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

		// 在 darwin 和 linux 上恢复原始 DNS。
		if manageSystemDNS() {
			if err := restoreDNSStepFn(m); err != nil {
				log.Warn("[TUN] restore system dns", "err", err)
			}
		}
	}

	m.running = false
	log.Info("[TUN] tun2socks stopped")
}

// stopEngine 停止 tun2socks engine，把错误记入日志而不是向上传播：
// 每个调用方都处在清理路径上，停止失败绝不能掩盖原始错误，
// 而上游的 StopOrFatal 会直接退出进程。
// Start 失败后再调用 Stop 是安全的：它只会释放
// 实际创建出来的设备和协议栈。
func stopEngine(reason string) {
	if err := engine.Stop(); err != nil {
		log.Warn("[TUN] engine stop", "reason", reason, "err", err)
	}
}

func (m *Manager) IsRunning() bool {
	return m.running
}

// SetICMPHandler 保存 ICMP handler 并把它注册到 engine。
// 在 Start() 之前或之后调用都安全；幂等。
func (m *Manager) SetICMPHandler(h *ICMPHandler) {
	m.icmpH = h
	engine.SetICMPHandler(h)
}

// DeviceConfig 返回填入了平台默认值的设备配置。
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
		// 脚本用非零退出码报告失败（参见
		// create_tun_dev_windows.bat 中的退出码契约）；
		// 它的输出会包含在返回的错误里。
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
		// 第三个参数是 TUN 设备的裸 IPv6 地址（不带 /prefix）：
		// 脚本删除持久化的 v6 地址，而创建脚本的
		// "add address" 会拒绝重复添加它。
		if _, err := util.CommandContext(ctx, "cmd.exe", "/C", namePath, d.Device, d.TunGW, bareV6Addr(d.TunIPV6Sub)); err != nil {
			log.Warn("[TUN] close script", "err", err)
		}
	case "darwin":
		// 与 helper 的 runCloseScript 参数顺序保持一致：
		// device, tunGW, localGateway, tunGWV6, serverIPV6, localGatewayV6。
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

// saveAndSetDNSStep 保存原始系统 DNS，并把系统切换到 TUN resolver。
// 它记录是否尝试过改动系统 DNS（dnsChanged，即使中途失败也会置位），
// restoreDNSStep 和 Start() 的失败回滚都以它为据：
// darwin 上手工配置的 DNS 保持不动，而把从未动过的 DNS
// 恢复回去会清空它（参见 restoreDNSStep）。
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
		// Linux 还必须把解析器固定到 TUN 设备：只给物理链路
		// 配置的 DNS 服务器，查询时 socket 会绑定到那条链路，
		// 于是查询从物理网卡发出而绕过隧道
		// （参见 util.SetSysDNSForTun）。
		setErr = util.SetSysDNSForTun(m.dev.Device, []string{m.cfg.DNSServer})
	} else if len(origin) == 0 {
		// Darwin：仅在系统没有配置自定义 DNS（即使用 DHCP 提供的
		// DNS）时才覆盖 DNS。如果用户手动设置了 DNS，
		// 则保留用户的选择。
		setErr = util.SetSysDNS([]string{m.cfg.DNSServer})
	} else {
		// Darwin 且配置了自定义 DNS：什么都没改动，因此什么也不用恢复，
		// 即使启动失败也是如此。
		return nil
	}

	// 设置过程可能在报告错误之前已应用了部分改动，因此只要尝试过
	// 就必须执行回滚。
	m.dnsChanged = true
	return setErr
}

// restoreDNSStep 撤销 saveAndSetDNSStep 的效果。除非系统 DNS 确实被
// 重新配置过，否则它是空操作：在 darwin 上，未改动过的系统会被写回
// "empty"，从而清空 DHCP 提供的服务器。
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

// sysDNSWithElevation 返回当前系统 DNS 服务器；在 darwin 上非 root
// 运行时通过 osascript 提权。
func sysDNSWithElevation() ([]string, error) {
	if runtime.GOOS == "darwin" && os.Geteuid() != 0 {
		return util.SysDNSViaOSAScript()
	}
	return util.SysDNS()
}

// setSysDNSWithElevation 设置系统 DNS 服务器；在 darwin 上非 root
// 运行时通过 osascript 提权。
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

// bareV6Addr 从 "address/prefix" 形式的子网字符串中去掉前缀长度
// （"2001:db8::1/64" -> "2001:db8::1"）：netsh add address 接受带
// /prefix 的形式，而 windows 关闭脚本里的 netsh delete address 需要
// 不带前缀的纯地址。
func bareV6Addr(sub string) string {
	addr, _, _ := strings.Cut(sub, "/")
	return addr
}
