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
	"sync"
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
	// ifaceMTU 返回接口当前的 MTU。它是包级变量，以便测试注入确定的接口表，
	// 无需真实创建 TUN 设备（真实设备需要 root 且会改写本机网络配置）。
	ifaceMTU = func(name string) (int, error) {
		iface, err := net.InterfaceByName(name)
		if err != nil {
			return 0, err
		}
		return iface.MTU, nil
	}
)

type Config struct {
	Socks5Addr       string
	Device           string
	DeviceFD         int  // 若 > 0，使用 fd:// scheme 打开设备而非按名称创建；0 表示按名称创建
	SkipRouteCleanup bool // darwin：helper 负责路由/DNS 清理，主进程在 Stop() 中跳过
	MTU              int  // TUN 设备与 tun2socks netstack 共用；<=0 取 config.DefaultTunMTU
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
	DNSServer        string // TUN 模式下要设置的 DNS 服务器（darwin/linux/windows）
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

	// mu 保护下面的生命周期字段。Start 在后台 goroutine 上运行（见
	// cmd/easyss.startTunEngine），而 Stop 可能来自托盘菜单或退出路径，
	// 两者并发执行：没有这把锁时，Stop 可能读到已发布但尚未创建的 done，
	// 从而在 nil channel 上永久阻塞（并因托盘持有 tunHelperMu 而卡住菜单）。
	mu      sync.Mutex
	running bool
	ctx     context.Context    // 用于取消进行中的 Start()
	cancel  context.CancelFunc // 保存下来，供 Stop() 取消 Start() goroutine
	done    chan struct{}      // Start() 结束（成功或失败）时关闭

	// stopMu 把整个 Stop 串行化：并发的第二个 Stop 必须等第一次拆除完成再返回，
	// 否则调用方会以为 TUN 已经停了（App.Stop 依赖"TUN 先于核心停止"这一顺序）。
	stopMu sync.Mutex
}

func New(cfg Config) *Manager {
	// MTU 的合法区间与默认值由 config.NormalizeTunMTU 统一定义：同一个值还要
	// 交给设备那一侧（各平台的创建脚本，见 createTunDevAndSetIPRoute；
	// darwin/linux 的直连路径上 tun2socks 也会按它设置设备），
	// 各自判断会立刻造成设备与 netstack 的 MTU 偏离。
	cfg.MTU = sharedconfig.NormalizeTunMTU(cfg.MTU)
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

// engineMTU 返回交给 tun2socks netstack 的 MTU。
//
// fd 路径（设备由提权 helper 创建后把 fd 传回）上设备先于 netstack 存在，而
// netstack 的 MTU 完全由本配置决定：它一旦小于设备的真实 MTU，tun2socks 的读
// 循环就会直接丢掉读到的、超过它的包（见 iobased dispatchLoop 的
// "n > mtu -> continue"）。TCP 恰好不受影响——netstack 通告的 MSS 由它的 MTU
// 推导，本机应用发不出超过它的段——所以故障只表现为 UDP、ICMP 与 IP 分片静默
// 失败，且没有任何报错可循。因此这里以设备的真实值为准（宁可偏离用户配置，
// 也不能静默丢包），并把这次偏离明确记入日志。
//
// 非 fd 路径不在这里判断：设备还不存在（或即将由 tun2socks 按同一个值重建），
// 而设备那一侧统一由创建脚本写入，因此交由 warnOnMTUMismatch 在脚本之后核对。
func (m *Manager) engineMTU() int {
	if m.cfg.DeviceFD <= 0 {
		return m.cfg.MTU
	}

	devMTU, err := ifaceMTU(m.cfg.Device)
	if err != nil {
		// 查不到设备（例如内核还没把接口名暴露出来）时保持配置值：这里既不能
		// 确认也不能修正，猜测一个 MTU 反而更危险。
		log.Warn("[TUN] read device mtu", "device", m.cfg.Device, "err", err)
		return m.cfg.MTU
	}

	if devMTU > m.cfg.MTU {
		// 封顶到 MaxTunMTU：设备的 MTU 超出可配置区间只可能是外部改动（例如
		// 别处执行了 "ip link set mtu"），而 netstack 的 MTU 同时决定每包读取
		// 缓冲的大小（tun2socks 的读循环按 offset + mtu 分配），没有理由跟着
		// 一个异常值走。TCP 不受封顶影响——本机应用发出的段不会超过我们通告的
		// MSS——只有超过该上限的 UDP/ICMP 报文会被丢弃，而这在日志里可见。
		raised := min(devMTU, sharedconfig.MaxTunMTU)
		log.Warn("[TUN] device mtu exceeds the configured netstack mtu, raising it to avoid dropping packets",
			"device", m.cfg.Device, "device_mtu", devMTU, "configured_mtu", m.cfg.MTU, "netstack_mtu", raised)
		return raised
	}
	if devMTU < m.cfg.MTU {
		// 不会丢包（netstack 的 MTU 只是上限），但设备才是决定本机应用 MSS 的
		// 那一侧，说明创建脚本没按配置把 MTU 写进设备，配置的 MTU 不会生效。
		log.Warn("[TUN] device mtu is smaller than the configured mtu, the device decides the path mtu",
			"device", m.cfg.Device, "device_mtu", devMTU, "configured_mtu", m.cfg.MTU)
	}
	return m.cfg.MTU
}

// warnOnMTUMismatch 在设备侧的 MTU 定稿之后核对它与 netstack 的 MTU 是否一致
// （调用点在 Start 中创建脚本之后）。非 fd 路径上设备 MTU 由创建脚本设置
// （Windows 用 netsh 写 wintun 适配器，darwin/linux 的脚本也会再应用一次），
// 只要有一处没跟上，就会出现 engineMTU 里描述的静默丢包。netstack 的 MTU 在
// 引擎启动后无法再改，因此这里只做记录——它把"配置了却没生效"变成日志里
// 看得见的事实。
func (m *Manager) warnOnMTUMismatch(netstackMTU int) {
	if m.cfg.DeviceFD > 0 {
		return // engineMTU 已经按设备真实值对齐过
	}

	devMTU, err := ifaceMTU(m.cfg.Device)
	if err != nil {
		return
	}
	if devMTU != netstackMTU {
		log.Warn("[TUN] device mtu differs from netstack mtu",
			"device", m.cfg.Device, "device_mtu", devMTU, "netstack_mtu", netstackMTU)
	}
}

func (m *Manager) Start() error {
	if scripts.CreateTunBytes == nil || scripts.CloseTunBytes == nil {
		return fmt.Errorf("tun: unsupported os %s", runtime.GOOS)
	}

	// 先建 done 再发布 cancel：Stop 是按"有 cancel 就等 done"的顺序工作的，
	// 反过来发布会让 Stop 在两步之间读到非 nil 的 cancel 与 nil 的 done，
	// 从而在 nil channel 上永久阻塞（见 mu 字段的说明）。
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})

	m.mu.Lock()
	m.ctx, m.cancel, m.done = ctx, cancel, done
	m.mu.Unlock()
	defer close(done)

	// 快速路径：还没开始就被取消了。
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	m.mu.Lock()
	icmpH := m.icmpH
	m.mu.Unlock()
	if icmpH != nil {
		engine.SetICMPHandler(icmpH)
	}

	fdMode := m.cfg.DeviceFD > 0
	device := m.cfg.Device
	if fdMode {
		device = "fd://" + strconv.Itoa(m.cfg.DeviceFD)
	}

	if err := ensureWintun(); err != nil {
		return fmt.Errorf("tun: extract wintun.dll: %w", err)
	}

	// MTU 在插入 key 之前定稿：fd 路径要与设备真实值对齐（见 engineMTU），
	// 引擎启动后就无法再改 netstack 的 MTU 了。
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
	case <-ctx.Done():
		engineStopFn("start cancelled")
		return ctx.Err()
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

	// MTU 核对放在创建脚本之后：设备侧的值是在那一步最终定稿的（fd 路径由
	// helper 的脚本写入，非 fd 路径由脚本再应用一次），因此此刻比较才有意义。
	// 若放在引擎启动之后，改过配置的首次启动会拿上一次会话遗留的适配器 MTU
	// 与新的 netstack MTU 比较，报出一条毫无意义的告警。
	m.warnOnMTUMismatch(mtu)

	// 最后检查：如果平台脚本运行期间 Stop() 取消了本次启动，
	// 撤销刚才建立的一切。
	select {
	case <-ctx.Done():
		engineStopFn("start cancelled")
		if !fdMode {
			if err := closeTunDevFn(m); err != nil {
				log.Warn("[TUN] close script after start cancellation", "err", err)
			}
		}
		if manageSystemDNS() {
			_ = restoreDNSStepFn(m)
		}
		return ctx.Err()
	default:
	}

	m.mu.Lock()
	m.running = true
	m.mu.Unlock()
	log.Info("[TUN] tun2socks started", "device", device, "proxy", m.cfg.Socks5Addr)
	return nil
}

// Stop 停止 tun2socks 并撤销它对系统做的改动。它幂等：对从未 Start 过、
// 或已经停止的实例调用都是安全的空操作；并发的 Stop 会串行执行，第二个调用者
// 等第一次拆除完成后再返回。
func (m *Manager) Stop() {
	m.stopMu.Lock()
	defer m.stopMu.Unlock()

	// 如果 Start() 仍在进行中，先取消它，
	// 等它完成清理后再继续。cancel/done 在同一把锁下快照：Start 先建 done
	// 再发布 cancel，因此这里绝不会在 nil channel 上等待。
	m.mu.Lock()
	cancel, done := m.cancel, m.done
	m.mu.Unlock()

	if cancel != nil && done != nil {
		cancel()
		log.Info("[TUN] Stop: waiting for Start goroutine to finish")
		<-done
		log.Info("[TUN] Stop: Start goroutine done")
	}

	m.mu.Lock()
	if !m.running {
		m.mu.Unlock()
		log.Info("[TUN] Stop: not running, returning")
		return
	}
	// 先落 running=false 再拆除：重复 Stop 与并发 Stop 都不会二次执行清理
	// （engine.Stop / 关脚本 / 恢复 DNS 都是"只能做一次"的动作）。
	m.running = false
	m.mu.Unlock()

	log.Info("[TUN] Stop: calling engine.Stop")
	engineStopFn("stop")
	log.Info("[TUN] Stop: engine.Stop done")

	if !m.cfg.SkipRouteCleanup {
		// 关闭脚本的失败不能改变 Stop 的结果（调用方已经在拆除了），但绝不能
		// 静默：脚本按"路由是否真的删掉"给出退出码，残留的分流默认路由会把
		// 全机 IPv4 流量送进一个没人读的 TUN 设备。
		if err := closeTunDevFn(m); err != nil {
			log.Warn("[TUN] close script", "err", err)
		}

		// 在 darwin 和 linux 上恢复原始 DNS。
		if manageSystemDNS() {
			if err := restoreDNSStepFn(m); err != nil {
				log.Warn("[TUN] restore system dns", "err", err)
			}
		}
	}

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

// IsRunning 报告 TUN 引擎当前是否处于运行状态。它由托盘读取以同步菜单，
// 而 Start/Stop 在其它 goroutine 上改写该状态，因此必须加锁。
func (m *Manager) IsRunning() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.running
}

// SetICMPHandler 保存 ICMP handler 并把它注册到 engine。
// 在 Start() 之前或之后调用都安全；幂等。
//
// 注意 handler 是借用的：它内部持有 core 的 StreamHandler 与 Router
// （见 cmd/easyss），而 engine 的注册是进程级全局，本类型既不关闭它也不注销它
// —— 关闭 core 必须先停止 TUN（App.Stop 已保证该顺序）。
func (m *Manager) SetICMPHandler(h *ICMPHandler) {
	m.mu.Lock()
	m.icmpH = h
	m.mu.Unlock()
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

	// linux 与 darwin 分支的最后一个实参都是 MTU：设备 MTU 由创建脚本设置
	// （与 Windows 脚本用 netsh 做的同一件事），因为 fd 路径下 tun2socks 拿到
	// 的只是 fd，改不了设备的 MTU，见 Manager.engineMTU。
	switch runtime.GOOS {
	case "linux":
		cmdArgs := []string{"pkexec", "bash", namePath, d.Device,
			ipSub(d.TunIP, d.TunMask), d.TunGW, d.LocalGateway,
			d.TunIPV6Sub, d.TunGWV6, d.ServerIPV6, d.LocalGatewayV6,
			strconv.Itoa(m.cfg.MTU)}
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
		// 第 8 个参数是系统 DNS（由 cmd/easyss 的 tunDNS 计算：本会话实测可达的
		// 内置/系统解析器，与 enable_forward_dns 无关），使 Windows 与
		// darwin/linux 的取值一致，不再由脚本硬编码。
		// 第 9 个参数是 MTU：wintun 适配器的 MTU 无法由 tun2socks 设置
		// （wireguard-go 只把它记在内存里，见 tun_windows.go 的 forcedMTU），
		// 只能由脚本用 netsh 写进接口；两侧不一致时 netstack 会静默丢弃
		// 超过自身 MTU 的 UDP/ICMP 包（见 Manager.engineMTU）。
		// 这里传 m.cfg.MTU：Windows 没有 fd 路径（没有提权 helper），
		// 因此它正是 engineMTU() 交给 netstack 的那个值。
		if _, err := util.CommandContext(ctx, "cmd.exe", "/C", namePath, d.Device,
			d.TunIP, d.TunGW, d.TunMask, d.TunIPV6Sub, d.TunGWV6, d.ServerIPV6,
			m.cfg.DNSServer, strconv.Itoa(m.cfg.MTU)); err != nil {
			return fmt.Errorf("tun: exec create script: %w", err)
		}
	case "darwin":
		// 两个分支必须传同一组实参（提权方式不同而已），因此都从
		// darwinScriptArgs 取值。
		args := darwinScriptArgs(d, m.cfg.MTU)
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

// closeTunDevAndDelIPRoute 运行平台的关闭脚本，删除本次会话安装的路由与设备。
//
// 它把脚本的失败原样返回（而不是像过去那样只记一条警告）：调用方要么是 Stop()
// 的拆除路径，要么是 Start() 失败后的回滚路径，还有可能是 fd/helper 路径下的
// 兜底回滚（见 CleanupTunDevice）。只要有一条分流默认路由残留，全机 IPv4 流量
// 就会进入一个没人读的 TUN 设备——也就是"停止 TUN 后断网"。
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
			return fmt.Errorf("tun: close script: %w", err)
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
			return fmt.Errorf("tun: close script: %w", err)
		}
	case "darwin":
		// 与 helper 的 runCloseScript 参数顺序保持一致：
		// device, tunGW, localGateway, tunGWV6, serverIPV6, localGatewayV6。
		// 两个分支必须传同一组实参（提权方式不同而已），因此都在这里构造。
		args := []string{d.Device, d.TunGW, d.LocalGateway, d.TunGWV6, d.ServerIPV6, d.LocalGatewayV6}
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

// CleanupTunDevice 重新执行平台的关闭脚本，供 fd/提权 helper 路径做兜底回滚：
// helper 退出后系统路由表里仍有指向 TUN 的路由时，非 root 的主进程自己删不掉
// 它们，只能再提权执行一次关闭脚本。
//
// cfg 必须与建立会话时使用的那一份一致（见 Manager.DeviceConfig 与
// cmd/easyss 的 tunSession）。它幂等：各平台的关闭脚本把"路由本来就不存在"
// 当作良性情况（见脚本的退出码契约），因此重复调用不会误报失败。
func CleanupTunDevice(cfg Config) error {
	return New(cfg).closeTunDevAndDelIPRoute()
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

// darwinScriptArgs 返回 create_tun_dev_darwin.sh 的实参，顺序与脚本的位置
// 参数一致：device、tun ip、tun gw、local gw、tun ipv6、tun gw ipv6、
// server ipv6、local gw ipv6、MTU。
//
// tun ipv6 传的是裸地址：darwin 脚本自己把 "/64" 拼到 ifconfig 的 inet6
// 参数上，而 TunIPV6Sub 是按 linux 脚本的 "ip -6 addr replace" 需要 CIDR
// 形式携带前缀长度的（默认 "2001:0db8:0:f101::1/64"）。直接把 TunIPV6Sub
// 交给 darwin 脚本会拼出 "2001:0db8:0:f101::1/64/64"，ifconfig 报
// "bad value" 并以退出码 1 结束，创建脚本整体失败、TUN 起不来。
func darwinScriptArgs(d DeviceConfig, mtu int) []string {
	return []string{
		d.Device, d.TunIP, d.TunGW, d.LocalGateway,
		bareV6Addr(d.TunIPV6Sub), d.TunGWV6, d.ServerIPV6, d.LocalGatewayV6,
		strconv.Itoa(mtu),
	}
}

// bareV6Addr 从 "address/prefix" 形式的子网字符串中去掉前缀长度
// （"2001:db8::1/64" -> "2001:db8::1"）：windows 关闭脚本里的
// netsh delete address 需要不带前缀的纯地址，而 darwin 创建脚本会自己
// 补上前缀长度，两者都拒绝 TunIPV6Sub 携带的 CIDR 形式。
func bareV6Addr(sub string) string {
	addr, _, _ := strings.Cut(sub, "/")
	return addr
}

// osascriptRunScript 返回以管理员权限执行 sh 脚本的 AppleScript 源码。
//
// 实参必须逐项加引号后拼接，不能直接 strings.Join 或用 "%s %s" 展开：
// ServerIPV6（服务端只有 IPv4 时为空）与 LocalGatewayV6（本机没有 IPv6 时为
// 空）都可能是空串，未加引号的空实参会被 shell 的词分割丢掉，它后面的位置
// 参数整体前移——创建脚本会把本地网关 v6 当成 server_ip_v6，在服务端没有
// IPv6 时照样安装 ::/0 默认路由；关闭脚本则会把 local_gateway_v6 当作空串删掉。
// root 路径与 helper 走 exec 直接传参，不受影响。
func osascriptRunScript(scriptPath string, args []string) string {
	quoted := make([]string, 0, len(args)+1)
	quoted = append(quoted, shellQuote(scriptPath))
	for _, arg := range args {
		quoted = append(quoted, shellQuote(arg))
	}
	return fmt.Sprintf("do shell script \"sh %s\" with administrator privileges",
		strings.Join(quoted, " "))
}

// shellQuote 用单引号包裹一个实参，使空串与含空格的实参都作为独立的位置参数
// 传给 sh。实参里的单引号按 POSIX shell 的惯例用 '\” 结束-转义-重开。
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
