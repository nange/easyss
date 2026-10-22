package tun

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nange/easyss/v3/client/tun/scripts"
	"github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/util"
	"github.com/xjasonlyu/tun2socks/v2/engine"
)

const (
	tunTCPSendBufferSize    = "1MB"
	tunTCPReceiveBufferSize = "256KB"
)

// 平台创建脚本失败的标记：托盘靠 errors.Is 区分，而不是匹配错误文本。
var ErrCreateDevice = errors.New("tun: create device")

// platform 是 TUN 会话的平台操作：设备脚本、系统 DNS 与 tun2socks 引擎。归 Manager
// 所有，测试构造自己的实例即可注入，无需改动包级状态。
type platform struct {
	createDev   func(*Manager) error
	closeDev    func(*Manager) error
	saveDNS     func(*Manager) error
	restoreDNS  func(*Manager) error
	engineStart func() error
	engineStop  func(string)
	settle      func()
	ifaceMTU    func(string) (int, error)
}

func defaultPlatform() platform {
	return platform{
		createDev:   func(m *Manager) error { return m.createTunDevAndSetIPRoute() },
		closeDev:    func(m *Manager) error { return m.closeTunDevAndDelIPRoute() },
		saveDNS:     func(m *Manager) error { return m.saveAndSetDNSStep() },
		restoreDNS:  func(m *Manager) error { return m.restoreDNSStep() },
		engineStart: func() error { return engine.Start() },
		engineStop:  func(reason string) { stopEngine(reason) },
		settle:      func() { time.Sleep(500 * time.Millisecond) },
		ifaceMTU: func(name string) (int, error) {
			iface, err := net.InterfaceByName(name)
			if err != nil {
				return 0, err
			}
			return iface.MTU, nil
		},
	}
}

type Config struct {
	Socks5Addr     string
	Device         string
	DeviceFD       int // > 0 时用 fd:// scheme 打开设备，0 表示按名称创建
	MTU            int // TUN 设备与 tun2socks netstack 共用；<=0 取默认值
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
	DNSServer      string
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
	originDNS  []string // TUN 启动前的原始系统 DNS（仅 darwin/linux）
	dnsChanged bool     // saveAndSetDNSStep 是否尝试过改动系统 DNS（即使中途失败也会置位，供回滚判断）
	icmpH      *ICMPHandler

	// mu 保护下面的生命周期字段：Start 在后台 goroutine 上运行，Stop 可能来自托盘或退出路径。
	mu      sync.Mutex
	started bool // Start 已进入（决定 Stop 是否需要等 done）
	running bool
	ctx     context.Context
	cancel  context.CancelFunc
	done    chan struct{} // Start 结束（成功或失败）时关闭

	// 记录本次会话真的做成了哪几步，拆除据此决定回收什么（见 teardown.go）。
	owner      Owner // 路由与 DNS 归谁回收
	engineUp   bool
	deviceUp   bool // 创建脚本可能已装上东西（失败时也可能是 true）
	dnsTouched bool // 系统 DNS 已被本进程改动
	tornDown   bool // teardown 已执行（关脚本与恢复 DNS 只能做一次）

	// 整个 Stop 串行化：并发的第二个 Stop 必须等第一次拆除完成，否则调用方会以为 TUN 已经停了。
	stopMu sync.Mutex

	plat platform
}

func New(cfg Config) *Manager {
	// MTU 的区间与默认值统一由 config.NormalizeTunMTU 决定：同一个值还要交给设备那一侧。
	cfg.MTU = config.NormalizeTunMTU(cfg.MTU)
	if cfg.UDPTimeout <= 0 {
		cfg.UDPTimeout = 5 * time.Minute
	}
	if cfg.LogLevel == "" {
		cfg.LogLevel = "warn"
	}
	if cfg.Device == "" {
		if runtime.GOOS == "darwin" {
			cfg.Device = config.DefaultTunDeviceNameDarwin
		} else {
			cfg.Device = config.DefaultTunDeviceName
		}
	}
	if cfg.Interface == "" || cfg.LocalGateway == "" {
		gw, dev, err := util.SysGatewayAndDevice()
		if err == nil {
			// 跳过 easyss 自身的 TUN 设备：上次会话残留的路由会让探测解析到它。
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

	// 会话状态在这里建好：Stop 可能在 Start 所在 goroutine 被调度之前就到达。
	startCtx, cancel := context.WithCancel(context.Background())
	startDone := make(chan struct{})

	return &Manager{
		cfg:    cfg,
		ctx:    startCtx,
		cancel: cancel,
		done:   startDone,
		plat:   defaultPlatform(),
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

func manageSystemDNS() bool {
	return managesSystemDNSFor(Platform())
}

// "该平台是否管理系统 DNS"的唯一判据；显式 platform 让平台矩阵能在任何宿主机上断言。
func managesSystemDNSFor(platform ScriptPlatform) bool {
	return platform == PlatformDarwin || platform == PlatformLinux
}

// fd 还没进入引擎的两处早退点（engine.Start 之前被取消、validateEngineKey 拒绝）在这里
// 关闭；进了 engine.Start 之后 fd 归上游，失败由 engine.Stop 兜底。
func (m *Manager) releaseUnownedFD(cause error) error {
	fd := m.cfg.DeviceFD
	if fd <= 0 {
		return cause
	}
	if err := closeRawDeviceFD(fd); err != nil {
		log.Warn("[TUN] release unowned device fd", "fd", fd, "err", err)
	}
	return cause
}

// fd 路径上 netstack 的 MTU 小于设备真实值时 tun2socks 会静默丢掉超限包（UDP、ICMP
// 与 IP 分片失败且无从报错），因此以设备真实值为准。
func (m *Manager) engineMTU() int {
	if m.cfg.DeviceFD <= 0 {
		return m.cfg.MTU
	}

	devMTU, err := m.plat.ifaceMTU(m.cfg.Device)
	if err != nil {
		// 查不到设备时保持配置值：既不能确认也不能修正，猜一个 MTU 更危险。
		log.Warn("[TUN] read device mtu", "device", m.cfg.Device, "err", err)
		return m.cfg.MTU
	}

	if devMTU > m.cfg.MTU {
		// 设备 MTU 超出可配置区间只可能是外部改动，封顶到 MaxTunMTU（netstack 的 MTU 决定每包读取缓冲）。
		raised := min(devMTU, config.MaxTunMTU)
		log.Warn("[TUN] device mtu exceeds the configured netstack mtu, raising it to avoid dropping packets",
			"device", m.cfg.Device, "device_mtu", devMTU, "configured_mtu", m.cfg.MTU, "netstack_mtu", raised)
		return raised
	}
	if devMTU < m.cfg.MTU {
		log.Warn("[TUN] device mtu is smaller than the configured mtu, the device decides the path mtu",
			"device", m.cfg.Device, "device_mtu", devMTU, "configured_mtu", m.cfg.MTU)
	}
	return m.cfg.MTU
}

// netstack 的 MTU 启动后无法再改，只能在创建脚本之后核对。
func (m *Manager) warnOnMTUMismatch(netstackMTU int) {
	if m.cfg.DeviceFD > 0 {
		return // engineMTU 已按设备真实值对齐
	}

	devMTU, err := m.plat.ifaceMTU(m.cfg.Device)
	if err != nil {
		return
	}
	if devMTU != netstackMTU {
		log.Warn("[TUN] device mtu differs from netstack mtu",
			"device", m.cfg.Device, "device_mtu", devMTU, "netstack_mtu", netstackMTU)
	}
}

func (m *Manager) Start() (err error) {
	if scripts.CreateTunBytes == nil || scripts.CloseTunBytes == nil {
		return fmt.Errorf("tun: unsupported os %s", runtime.GOOS)
	}

	// 必须在做任何系统改动之前就让 Stop 看见"启动已进入"，否则 Stop 会等一个永不关闭的 done。
	m.mu.Lock()
	if m.started {
		m.mu.Unlock()
		return fmt.Errorf("tun: manager already started")
	}
	m.started = true
	m.owner = ownerForConfig(m.cfg)
	ctx, done, owner := m.ctx, m.done, m.owner
	m.mu.Unlock()

	// 成功只关 done（拆除归 Stop），失败或被取消则由本次 Start 自己拆掉已建起的东西。
	defer func() {
		if err == nil {
			close(done)
			return
		}
		reason := ReasonStartFailed
		switch {
		case ctx.Err() != nil:
			reason = ReasonStartCancelled
		case errors.Is(err, ErrCreateDevice):
			reason = ReasonCreateFailed
		}
		if terr := m.teardown(reason, owner); terr != nil {
			// 拆除失败不改变 Start 的错误，但必须留下痕迹：残留路由就是"停止 TUN 后断网"的成因。
			log.Warn("[TUN] start rollback left something behind", "reason", reason.String(), "err", terr)
		}
		close(done)
	}()

	select {
	case <-ctx.Done():
		return m.releaseUnownedFD(ctx.Err())
	default:
	}

	m.mu.Lock()
	icmpH := m.icmpH
	m.mu.Unlock()
	if icmpH != nil {
		engine.SetICMPHandler(icmpH)
	}

	device := m.cfg.Device
	if owner == OwnerHelper {
		device = "fd://" + strconv.Itoa(m.cfg.DeviceFD)
	}

	key, err := m.prepareEngine(device)
	if err != nil {
		return err
	}
	if err := m.startEngine(key); err != nil {
		return err
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	m.plat.settle()

	if owner == OwnerLocal {
		if err := m.configureLocalDevice(); err != nil {
			return err
		}
	}

	// 核对放在创建脚本之后：设备侧的值在那一步才定稿，否则会拿上一次会话遗留的适配器 MTU 比较。
	m.warnOnMTUMismatch(key.MTU)

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	m.mu.Lock()
	m.running = true
	m.mu.Unlock()
	log.Info("[TUN] tun2socks started", "device", device, "proxy", m.cfg.Socks5Addr)
	return nil
}

// prepareEngine 构造并校验 engine.Key；validateEngineKey 拒绝时释放尚未交给引擎的 fd。
func (m *Manager) prepareEngine(device string) (*engine.Key, error) {
	if err := ensureWintun(); err != nil {
		return nil, fmt.Errorf("tun: extract wintun.dll: %w", err)
	}

	// MTU 必须在插入 key 之前定稿：引擎启动后就无法再改 netstack 的 MTU。
	mtu := m.engineMTU()

	key := &engine.Key{
		MTU:                      mtu,
		Device:                   device,
		LogLevel:                 m.cfg.LogLevel,
		UDPTimeout:               m.cfg.UDPTimeout,
		Proxy:                    m.cfg.Socks5Addr,
		TCPModerateReceiveBuffer: true,
		TCPSendBufferSize:        tunTCPSendBufferSize,
		TCPReceiveBufferSize:     tunTCPReceiveBufferSize,
	}

	// 引擎在 parseDevice 之前就会拒绝的配置必须先在这里拒掉：进入 engine.Start 之后 fd 已归 tun2socks，
	// 失败时 engine.Stop 是空操作（设备没记进 _defaultDevice）。
	if err := validateEngineKey(key); err != nil {
		return nil, m.releaseUnownedFD(err)
	}
	return key, nil
}

// startEngine 把 key 插入引擎并启动；失败时 engine.Stop 是唯一能关闭已打开设备的路径。
func (m *Manager) startEngine(key *engine.Key) error {
	engine.Insert(key)

	// 上游 engine.Start 返回错误而不是 log.Fatalf，失败时它可能已打开 TUN 设备。
	if err := m.plat.engineStart(); err != nil {
		// validateEngineKey 已放行，因此失败必然发生在 parseDevice 或其之后：fd 已被引擎接管，
		// 而 tun2socks 的失败路径不清理，关闭权只在这里的 engine.Stop。
		m.plat.engineStop(ReasonStartFailed.String())
		return fmt.Errorf("tun: start engine: %w", err)
	}
	m.mu.Lock()
	m.engineUp = true
	m.mu.Unlock()
	return nil
}

// configureLocalDevice 处理本进程拥有设备的分支：保存 DNS、标记 deviceUp 并执行创建脚本。
func (m *Manager) configureLocalDevice() error {
	if manageSystemDNS() {
		if err := m.plat.saveDNS(m); err != nil {
			log.Warn("[TUN] set system dns", "err", err)
		}
		m.mu.Lock()
		m.dnsTouched = true
		m.mu.Unlock()
	}

	// 创建脚本可能在报失败之前已装上地址与部分路由，因此 deviceUp 在调用之前置位。
	m.mu.Lock()
	m.deviceUp = true
	m.mu.Unlock()
	if err := m.plat.createDev(m); err != nil {
		return fmt.Errorf("%w: %w", ErrCreateDevice, err)
	}
	return nil
}

// 从调用方看不出"从未 Start"与"Start 还没被调度到"的区别，因此无条件落下停止意图，
// 只在 started 时等 done。
func (m *Manager) Stop() {
	m.stopMu.Lock()
	defer m.stopMu.Unlock()

	m.mu.Lock()
	if m.cancel != nil {
		m.cancel()
	}
	started, done := m.started, m.done
	m.mu.Unlock()

	if started {
		log.Info("[TUN] Stop: waiting for Start goroutine to finish")
		<-done
		log.Info("[TUN] Stop: Start goroutine done")
	}

	m.mu.Lock()
	owner, running := m.owner, m.running
	m.running = false
	m.mu.Unlock()

	// 拆除与是否曾成功启动无关：两者的 teardown 共用 tornDown 标记。running 只是托盘显示开/关的判据。
	if !running && !m.hasSomethingToTearDown() {
		log.Info("[TUN] Stop: nothing to tear down, returning")
		return
	}

	if err := m.teardown(ReasonStop, owner); err != nil {
		log.Warn("[TUN] Stop: teardown reported a failure", "err", err)
	}
	log.Info("[TUN] tun2socks stopped")
}

// 让 Stop 在从未 Start 时保持空操作，又不漏掉半途失败留下的残局。
func (m *Manager) hasSomethingToTearDown() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.engineUp || m.deviceUp || m.dnsTouched
}

// 错误只记日志：调用方都在清理路径上，而上游的 StopOrFatal 会直接退出进程。
func stopEngine(reason string) {
	if err := engine.Stop(); err != nil {
		log.Warn("[TUN] engine stop", "reason", reason, "err", err)
	}
}

func (m *Manager) IsRunning() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.running
}

// handler 是借用的（持有 core 的 StreamHandler 与 Router），而注册是进程级全局，
// 因此关闭 core 必须先停 TUN。
func (m *Manager) SetICMPHandler(h *ICMPHandler) {
	m.mu.Lock()
	m.icmpH = h
	m.mu.Unlock()
	engine.SetICMPHandler(h)
}

func (m *Manager) DeviceConfig() DeviceConfig {
	return m.dev
}

func (m *Manager) createTunDevAndSetIPRoute() error {
	if scripts.CreateTunBytes == nil {
		return fmt.Errorf("tun: no create script for %s", runtime.GOOS)
	}

	ctx, cancel := context.WithTimeout(m.ctx, 60*time.Second)
	defer cancel()

	namePath, err := WriteScriptToTemp(scripts.CreateTunFilename, scripts.CreateTunBytes)
	if err != nil {
		return fmt.Errorf("tun: write create script: %w", err)
	}
	defer os.RemoveAll(namePath) //nolint:errcheck

	d := m.dev

	// 位置参数一律由 ScriptArgs 渲染（见 script_args.go）：三平台位次不同，抄错只会在
	// 运行时由脚本的 "failed near" 暴露。
	args := NewScriptArgs(d, m.cfg.DNSServer, m.cfg.MTU).Create()

	switch runtime.GOOS {
	case "linux":
		cmdArgs := append([]string{"pkexec", "bash", namePath}, args...)
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
		// 脚本用非零退出码报告失败，其输出会包含在返回的错误里。
		if _, err := util.CommandContext(ctx, "cmd.exe", append([]string{"/C", namePath}, args...)...); err != nil {
			return fmt.Errorf("tun: exec create script: %w", err)
		}
	case "darwin":
		if os.Geteuid() == 0 {
			if _, err := util.CommandContext(ctx, "sh", append([]string{namePath}, args...)...); err != nil {
				return fmt.Errorf("tun: exec create script: %w", err)
			}
		} else {
			cmd := osascriptRunScript(namePath, args)
			if _, err := util.CommandContext(ctx, "osascript", "-e", cmd); err != nil {
				return fmt.Errorf("tun: exec create script: %w", err)
			}
		}
	}
	return nil
}

// 失败必须原样返回：残留一条分流默认路由，全机 IPv4 流量就会进入没人读的 TUN 设备。
func (m *Manager) closeTunDevAndDelIPRoute() error {
	if scripts.CloseTunBytes == nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	namePath, err := WriteScriptToTemp(scripts.CloseTunFilename, scripts.CloseTunBytes)
	if err != nil {
		return fmt.Errorf("tun: write close script: %w", err)
	}
	defer os.RemoveAll(namePath) //nolint:errcheck

	// 关闭脚本的位次同样由 ScriptArgs 渲染：windows 的第 3 位是裸 IPv6 地址，linux 只读设备名。
	args := NewScriptArgs(m.dev, m.cfg.DNSServer, m.cfg.MTU).Close()

	switch runtime.GOOS {
	case "linux":
		cmdArgs := append([]string{"pkexec", "bash", namePath}, args...)
		if os.Geteuid() == 0 {
			cmdArgs = cmdArgs[1:]
		}
		if _, err := util.CommandContext(ctx, cmdArgs[0], cmdArgs[1:]...); err != nil {
			return fmt.Errorf("tun: close script: %w", err)
		}
	case "windows":
		dir := filepath.Dir(namePath)
		newNamePath := filepath.Join(dir, scripts.CloseTunFilename)
		if err := os.Rename(namePath, newNamePath); err != nil {
			return fmt.Errorf("tun: rename close script: %w", err)
		}
		namePath = newNamePath
		if _, err := util.CommandContext(ctx, "cmd.exe", append([]string{"/C", namePath}, args...)...); err != nil {
			return fmt.Errorf("tun: close script: %w", err)
		}
	case "darwin":
		if os.Geteuid() == 0 {
			if _, err := util.CommandContext(ctx, "sh", append([]string{namePath}, args...)...); err != nil {
				return fmt.Errorf("tun: close script: %w", err)
			}
		} else {
			cmd := osascriptRunScript(namePath, args)
			if _, err := util.CommandContext(ctx, "osascript", "-e", cmd); err != nil {
				return fmt.Errorf("tun: close script: %w", err)
			}
		}
	}
	return nil
}

// 重新执行平台的关闭脚本，供 fd/提权 helper 路径兜底回滚：非 root 的主进程删不掉
// helper 装的路由。cfg 必须与建立会话时一致；脚本把"路由本来就不存在"当良性情况。
func CleanupTunDevice(cfg Config) error {
	return New(cfg).closeTunDevAndDelIPRoute()
}

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
		// Linux 还必须把解析器固定到 TUN 设备：只配 DNS 服务器的话，查询 socket 会绑定
		// 到那条物理链路，从物理网卡发出而绕过隧道（见 util.SetSysDNSForTun）。
		setErr = util.SetSysDNSForTun(m.dev.Device, []string{m.cfg.DNSServer})
	} else if len(origin) == 0 {
		// Darwin：只在系统没有自定义 DNS（用 DHCP 提供的）时才覆盖，恢复从未动过的 DNS 会清空它。
		setErr = util.SetSysDNS([]string{m.cfg.DNSServer})
	} else {
		return nil
	}

	m.dnsChanged = true
	return setErr
}

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

func sysDNSWithElevation() ([]string, error) {
	if runtime.GOOS == "darwin" && os.Geteuid() != 0 {
		return util.SysDNSViaOSAScript()
	}
	return util.SysDNS()
}

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

// 实参必须逐项加引号：空实参被 shell 丢弃会让后面的位置参数整体前移，
// 创建脚本就会装出不存在的 ::/0 默认路由。
func osascriptRunScript(scriptPath string, args []string) string {
	quoted := make([]string, 0, len(args)+1)
	quoted = append(quoted, shellQuote(scriptPath))
	for _, arg := range args {
		quoted = append(quoted, shellQuote(arg))
	}
	return fmt.Sprintf("do shell script \"sh %s\" with administrator privileges",
		strings.Join(quoted, " "))
}

// 单引号让空串与含空格的实参都作为独立的位置参数；实参里的单引号按 POSIX 惯例结束-转义-重开。
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
