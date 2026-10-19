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
	Socks5Addr     string
	Device         string
	DeviceFD       int // 若 > 0，使用 fd:// scheme 打开设备而非按名称创建；0 表示按名称创建
	MTU            int // TUN 设备与 tun2socks netstack 共用；<=0 取 config.DefaultTunMTU
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
	DNSServer      string // TUN 模式下要设置的 DNS 服务器（darwin/linux/windows）
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
	//
	// 会话状态在 New 里就建好（而不是在 Start 里）：Start 由调用方派发的
	// goroutine 执行，从 tunUp 返回到那个 goroutine 真正进入 Start 之间有一个
	// 调度窗口，托盘的下一次点击可以在窗口内到达 Stop。若 ctx/cancel 只在
	// Start 里创建，Stop 在那个窗口里只会看到"从未启动"并直接返回，而 Start
	// 随后照常把引擎、路由与系统 DNS 全部建立起来——session 那边却已经把
	// manager 收走并发布了 EnableTun2socks=false：界面说关了，流量还在隧道里，
	// 而且再没有人持有这个 manager 去停它（下一次点击会新建一套，engine 的包级
	// 默认设备被覆盖，前一套再也停不掉）。因此停止意图必须有一个在 New 时就
	// 存在的落点。
	mu      sync.Mutex
	started bool               // Start 已进入（决定 Stop 是否需要等 done）
	running bool               // 本次会话已成功建立（Stop 后的拆除以它为准）
	ctx     context.Context    // 用于取消进行中的 Start()；New 时创建
	cancel  context.CancelFunc // 供 Stop() 表达"停止"意图；New 时创建
	done    chan struct{}      // Start() 结束（成功或失败）时关闭

	// 拆除状态（见 teardown.go）。owner 在 Start 认领会话时定稿，之后只读；
	// 三个 bool 记录本次会话真的做成了哪几步，拆除按它们决定回收什么——
	// 这就是过去 fdMode / SkipRouteCleanup / helperSignalled 三套隐式条件的替代。
	owner      Owner // 路由与 DNS 归谁回收
	engineUp   bool  // engineStartFn 已成功
	deviceUp   bool  // 创建脚本可能已装上东西（失败时也可能是 true）
	dnsTouched bool  // 系统 DNS 已被本进程改动
	tornDown   bool  // teardown 已执行（关脚本与恢复 DNS 只能做一次）

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

	// 会话状态在这里建好：Stop 可能在 Start 所在 goroutine 被调度之前就到达
	// （见 mu 字段的说明）。done 保持打开，直到 Start 真正跑完才关闭。
	startCtx, cancel := context.WithCancel(context.Background())
	startDone := make(chan struct{})

	return &Manager{
		cfg:    cfg,
		ctx:    startCtx,
		cancel: cancel,
		done:   startDone,
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
	return managesSystemDNSFor(Platform())
}

// managesSystemDNSFor 是"该平台是否由 client/tun 管理系统 DNS"的唯一判据。
// 它接收显式的 ScriptPlatform（而不是读 runtime.GOOS），使得平台矩阵可以在
// 任何宿主机上断言 windows 的豁免——否则那条断言只能在 windows 上运行。
func managesSystemDNSFor(platform ScriptPlatform) bool {
	return platform == PlatformDarwin || platform == PlatformLinux
}

// releaseUnownedFD 在**本 goroutine 能证明 fd 尚未进入引擎**的两处早退点关掉
// 它（fd 路径），并返回原错误。
//
// 只有这两处是安全的：一是在 engine.Insert 之前就被取消，二是 validateEngineKey
// 拒绝了配置。两者都还没调用 engine.Start，fd 的所有权毫无疑问仍在本次调用手里。
// 一旦进了 engine.Start，fd 的归属就交给上游了（parseDevice 内部可能已包装成
// 设备、也可能在它之前失败），那时的失败由 engine.Stop 兜底，本进程不再插手：
// 只看得到一个整数是没法安全判断"这个号码现在还是不是我的设备"的。
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

func (m *Manager) Start() (err error) {
	if scripts.CreateTunBytes == nil || scripts.CloseTunBytes == nil {
		return fmt.Errorf("tun: unsupported os %s", runtime.GOOS)
	}

	// 会话状态由 New 建立（见 mu 字段），这里只认领它：Start 只能跑一次，
	// 且必须在做任何系统改动之前就让 Stop 能看见"启动已进入"——否则 Stop
	// 会等到一个永远不会关闭的 done，或者（更糟）在 Start 之前返回而让这次
	// 启动照常成功。
	m.mu.Lock()
	if m.started {
		m.mu.Unlock()
		return fmt.Errorf("tun: manager already started")
	}
	m.started = true
	m.owner = ownerForConfig(m.cfg)
	ctx, done, owner := m.ctx, m.done, m.owner
	m.mu.Unlock()

	// createFailed 标记"失败发生在创建脚本里"。创建脚本可能在汇报失败之前
	// 已经装上了地址与部分路由，是唯一一类"必然有东西要删"的失败，因此它
	// 有自己的 TeardownReason（日志与错误呈现口径不同）。
	createFailed := false

	// 无论从哪条路径退出都会走这里：成功则只关 done（拆除归 Stop），失败或
	// 被取消则由本次 Start 自己拆掉已经建起来的东西。reason 只影响日志与错误
	// 呈现口径：取消是用户操作的结果，失败需要用户看错误，两者可操作性不同。
	defer func() {
		if err == nil {
			close(done)
			return
		}
		reason := ReasonStartFailed
		switch {
		case ctx.Err() != nil:
			reason = ReasonStartCancelled
		case createFailed:
			reason = ReasonCreateFailed
		}
		if terr := m.teardown(reason, owner); terr != nil {
			// 拆除失败不改变 Start 的错误（它已经说明了问题），但必须在日志里
			// 留下痕迹：残留的路由是"停止 TUN 后断网"的成因。
			log.Warn("[TUN] start rollback left something behind", "reason", reason.String(), "err", terr)
		}
		close(done)
	}()

	// 快速路径：还没开始就被取消了（Stop 先到，或调用方在 stop 之后再 Start）。
	// 这里 fd 显然还没进入引擎，因此由本进程关它是安全的——再往后就不再有
	// "显然"可言了，见下面 validateEngineKey 的说明。
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

	// 引擎会在 parseDevice 之前的步骤里拒绝的配置，必须先在这里拒掉：那一步
	// 之后 fd 已经归 tun2socks，失败时它既不会记进 _defaultDevice（engine.Stop
	// 因此是空操作），也可能已经把它包装成设备。也就是说，"engine.Start 失败
	// 时 fd 归谁"在 parseDevice 之前是不确定的，而在它之前拒掉这类配置，
	// 就把这个不确定区间缩到了 "fd 已经交给引擎" 之后——那里由 engine.Stop
	// 负责关闭，不需要本进程再猜。
	if err := validateEngineKey(key); err != nil {
		return m.releaseUnownedFD(err)
	}

	engine.Insert(key)

	// 上游把 Start 改成了返回错误而不是 log.Fatalf
	// （tun2socks #550/#552）：把失败报告给调用方而不是退出进程，
	// 并释放 Start 在 core.CreateStack 失败之前可能已打开的
	// TUN 设备。
	if err := engineStartFn(); err != nil {
		// 走到这里说明 validateEngineKey 已经放行，因此失败必然发生在
		// parseDevice 或其之后：fd 已被引擎接管，而 tun2socks 的失败路径
		// 不清理（#550/#552），关闭权只在这里的 engine.Stop。
		//
		// engineUp 尚未置位，teardown 不会替我们调它，所以必须显式释放。
		// engine.Stop 是幂等的：parseDevice 内部失败时它也安全。
		//
		// 这次释放不在 teardown 的 tornDown 状态机里，但 Start 只成功认领
		// 一次会话，因此最多执行一次；之后的 Stop 依赖 engine.Stop 幂等
		// （回归测试 TestManagerEngineStartFailureReleasesTheDevice 钉住了
		// "Stop 不会再停一次"）。
		engineStopFn(ReasonStartFailed.String())
		return fmt.Errorf("tun: start engine: %w", err)
	}
	m.mu.Lock()
	m.engineUp = true
	m.mu.Unlock()

	// 在改动路由 / DNS 之前，允许 Stop() 取消本次启动。
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	settleDelay()

	if owner == OwnerLocal {
		// 在 darwin 和 linux 上保存原始 DNS 并设置 TUN DNS。
		if manageSystemDNS() {
			if err := saveAndSetDNSStepFn(m); err != nil {
				log.Warn("[TUN] set system dns", "err", err)
			}
			m.mu.Lock()
			m.dnsTouched = true
			m.mu.Unlock()
		}

		// 创建脚本可能在报告失败之前已经装上了地址与部分路由，因此
		// deviceUp 在调用之前就置位：拆除必须假设"路由可能已经在了"。
		// 删除路由是幂等的，只在这条刚运行过创建脚本的路径上才有意义。
		m.mu.Lock()
		m.deviceUp = true
		m.mu.Unlock()
		if err := createTunDevFn(m); err != nil {
			createFailed = true
			return fmt.Errorf("tun: create device: %w", err)
		}
	}

	// MTU 核对放在创建脚本之后：设备侧的值是在那一步最终定稿的（fd 路径由
	// helper 的脚本写入，非 fd 路径由脚本再应用一次），因此此刻比较才有意义。
	// 若放在引擎启动之后，改过配置的首次启动会拿上一次会话遗留的适配器 MTU
	// 与新的 netstack MTU 比较，报出一条毫无意义的告警。
	m.warnOnMTUMismatch(mtu)

	// 最后检查：如果平台脚本运行期间 Stop() 取消了本次启动，defer 里的
	// teardown 会撤销刚才建立的一切。
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

// Stop 停止 tun2socks 并撤销它对系统做的改动。它幂等：对从未 Start 过、
// 或已经停止的实例调用都是安全的空操作；并发的 Stop 会串行执行，第二个调用者
// 等第一次拆除完成后再返回。
//
// "从未 Start"与"Start 还没被调度到"是两件不同的事，而调用方（托盘）分不出它们：
// session.tunUp 先在锁内发布 manager、再派发 goroutine，随后用户的下一次点击
// 可能落在那个 goroutine 进入 Start 之前。因此这里无条件落下停止意图（cancel），
// 并且只在 Start 真的已经进入时才等 done——两者在 mu 下一起快照，不存在
// "读到 cancel 却等一个永远不会关闭的 done"的窗口。
func (m *Manager) Stop() {
	m.stopMu.Lock()
	defer m.stopMu.Unlock()

	m.mu.Lock()
	if m.cancel != nil {
		// 无论 Start 是否已进入：先到的停止意图必须能被后到的 Start 看见。
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

	// 拆除与"是否曾成功启动"无关：Start 的失败路径可能已经装上了部分路由与
	// 系统 DNS，而它自己的 teardown 与这里共用同一个 tornDown 标记，先到者
	// 负责，后到者是空操作。running 仍是"托盘该显示开还是关"的判据。
	if !running && !m.hasSomethingToTearDown() {
		log.Info("[TUN] Stop: nothing to tear down, returning")
		return
	}

	if err := m.teardown(ReasonStop, owner); err != nil {
		log.Warn("[TUN] Stop: teardown reported a failure", "err", err)
	}
	log.Info("[TUN] tun2socks stopped")
}

// hasSomethingToTearDown 报告本次会话是否留下过需要回收的东西。它让 Stop 在
// "从未 Start 过"时保持空操作（不跑关闭脚本、不碰系统 DNS），同时不会漏掉
// Start 半途失败留下的残局。
func (m *Manager) hasSomethingToTearDown() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.engineUp || m.deviceUp || m.dnsTouched
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

	namePath, err := WriteScriptToTemp(scripts.CreateTunFilename, scripts.CreateTunBytes)
	if err != nil {
		return fmt.Errorf("tun: write create script: %w", err)
	}
	defer os.RemoveAll(namePath) //nolint:errcheck

	d := m.dev

	// 位置参数一律由 ScriptArgs 渲染（见 script_args.go）：三平台的位次不同
	// （windows 的第 4 位是掩码、第 8 位是 DNS），过去每个调用点各写一份字面量
	// 切片，抄错只会在运行时由脚本的 "failed near" 暴露。
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
		// 脚本用非零退出码报告失败（参见
		// create_tun_dev_windows.bat 中的退出码契约）；
		// 它的输出会包含在返回的错误里。
		if _, err := util.CommandContext(ctx, "cmd.exe", append([]string{"/C", namePath}, args...)...); err != nil {
			return fmt.Errorf("tun: exec create script: %w", err)
		}
	case "darwin":
		// 两个分支必须传同一组实参（提权方式不同而已），因此都从同一个
		// args 取值。
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

	namePath, err := WriteScriptToTemp(scripts.CloseTunFilename, scripts.CloseTunBytes)
	if err != nil {
		return fmt.Errorf("tun: write close script: %w", err)
	}
	defer os.RemoveAll(namePath) //nolint:errcheck

	// 关闭脚本的位次也由 ScriptArgs 统一渲染：windows 的第 3 位是裸 IPv6 地址，
	// linux/darwin 是六个按统一顺序补齐的网关（linux 的脚本只读设备名，多传的
	// 实参无害，只是与 darwin/helper 共用同一套布局）。
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
		// 两个分支必须传同一组实参（提权方式不同而已），因此都在这里构造。
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
