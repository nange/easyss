package main

import (
	"fmt"
	"io"
	"net/http"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nange/easyss/v3/client/config"
	"github.com/nange/easyss/v3/client/tun"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/pprof"
	"github.com/nange/easyss/v3/runner"
	"github.com/nange/easyss/v3/stats"
	"github.com/nange/easyss/v3/util"
)

// session 拥有一次"代理会话"的全部可变状态：运行中的核心、TUN 引擎（含提权
// helper 的句柄）、pprof 服务器、后台统计循环，以及两个会话级标量（启动警告、
// 是否因网络未就绪跳过了 TUN）。
//
// 这些字段过去散落在 App 与 TrayApp 上，由三把锁（App.stateMu、App.tunHelperMu、
// TrayApp.serverSwitchMu）加若干条"调用方持有某把锁"的注释约定保护，而同属一次
// TUN 会话的 tunMgr/tunSession/tunHelperStdin 还分居两个结构体。现在它们是本类型
// 的私有字段，只能通过下面的方法访问：
//
//   - 字段不可见：忘记持锁、拿错锁或从别的结构体顺手改写，都不再是"可以犯的错误"；
//   - 锁序（seqMu → mu → tunMu）是本文件内部的不变式，不再需要跨结构体维持；
//   - 单写者：改写会话字段的只有 start/stop/tunUp/tunDown/tunUpViaHelper 五个方法；
//   - 读侧不持锁：当前核心走原子指针（currentCore），因为后台统计 tick 与托盘菜单
//     处理器各自在自己的 goroutine 上读它，不能阻塞在秒级的 Start 或最长可达 60s
//     的 TUN 拆除上。
type session struct {
	app *App

	// mu 保护会话级字段：核心的安装/取下、pprof 服务器、统计循环、启动警告。
	// 它同时是"一次 Start/Stop 对运行期字段的全部改写"的串行化点。
	mu sync.Mutex

	// tunMu 保护一次 TUN 会话的三个字段（tunMgr/tunSession/tunHelperStdin）。
	// 它与 mu 分开是刻意的：TUN 开关只走这把锁，因此不会被秒级的 Start 挡住，
	// 也不会被 core.Stop()（可能等待在飞中继结束）挡住——stop 在锁内只"取走"
	// manager，真正等待引擎停止是在锁外做的（见 stop 的注释）。
	tunMu sync.Mutex

	// seqMu 串行化整套"停→起"序列：切换服务器、自更新重启、退出拆除。单次
	// Start/Stop 只走 mu，而一次序列要跨越多次 stop/start，需要一个更粗粒度的
	// 持有者（见 run）。它取代了 TrayApp.serverSwitchMu，并把"退出时的拆除"也
	// 纳入同一个序列——过去那是 closeService 整段持有 TrayApp.mu 顺带得到的性质。
	seqMu sync.Mutex

	// core 是当前运行的代理核心。读者在各自 goroutine 上无锁取快照，因此用原子
	// 指针发布这个事实：
	//   - core 一旦发布就不再变化，Start 装载、Stop 取下即停；
	//   - 读点只 Load 一次到局部变量——旧代码
	//     `core != nil && core.Client != nil` 这类两次读之间被 Stop 清空，
	//     是 nil 解引用，不只是数据竞争。
	core atomic.Pointer[runner.Core]

	pprofSrv *http.Server

	// startupWarn 记录首个非致命启动警告（例如服务端域名解析失败，或自定义规则
	// 文件加载失败）。客户端继续运行；托盘以系统通知形式呈现，headless 构建则记入
	// 日志。它是会话级状态：start 在会话起点重置它，读者一律走 startupWarn()。
	startupWarn error

	// tunSkippedForNetwork 记录启动时因服务端域名尚未解析成功（开机网络还没
	// 就绪）而跳过了 TUN；后台解析恢复后据此在通知里提醒用户手动开启。
	tunSkippedForNetwork bool

	// statsCloser 属于会话状态：start 换新通道，stop 关闭它。
	statsCloser chan struct{}

	// verifyTeardown 是拆除时"等提权 helper 退出 + 复核系统路由表"这一步，
	// 由平台文件提供实现（见 tray_tun_teardown_unix.go 的 platformTunTeardown 与
	// 它在其他平台上的空实现）。它是字段而不是直接调用，使测试可以在任何平台上
	// 替换它，不必为每个平台写一份按构建标签分文件的测试。
	verifyTeardown func(dev tun.DeviceConfig, helperSignalled bool) error

	// tunMgr 是当前 TUN 会话的引擎；tunSession 是它启用时实际使用的设备/网关
	// 配置（关闭时用它——而不是关闭时的 tunMgr——核对路由与回滚：fd 路径的
	// manager 只携带请求的设备名，而会话的本地网关等取值到关闭时可能已经变化）。
	// tunHelperStdin 是提权 helper 的 FIFO 写入端；关闭它以通知助手进程退出。
	tunMgr         *tun.Manager
	tunSession     *tun.DeviceConfig
	tunHelperStdin io.WriteCloser
}

func newSession(app *App) *session {
	return &session{app: app, verifyTeardown: platformTunTeardown}
}

// run 在序列锁下执行一次完整的"停→起"序列。切换服务器、自更新重启与退出拆除
// 都必须走这里：它们各自由新的 goroutine 驱动（托盘的每次点击一个），并发执行会
// 抢同一组本地端口（4080/5080）、把两套菜单勾选互相覆盖，甚至留下没有任何核心
// 在运行的状态。
//
// 序列体写成 ...InSequence 后缀的私有方法，只能从本包的 run/runErr 闭包里调用；
// 序列锁不可重入，因此序列体里不得再调用同样会取序列锁的入口（如 restartServiceWith）。
func (s *session) run(fn func()) {
	s.seqMu.Lock()
	defer s.seqMu.Unlock()
	fn()
}

// runErr 是 run 的回传错误版本：调用方需要知道这次序列的成败（例如切换服务器
// 失败要还原菜单勾选）。
func (s *session) runErr(fn func() error) error {
	s.seqMu.Lock()
	defer s.seqMu.Unlock()
	return fn()
}

// currentCore 返回当前核心的快照；nil 表示没有会话在运行。
func (s *session) currentCore() *runner.Core { return s.core.Load() }

// installCore 发布一次会话的核心。原子指针本身不需要锁；改写"当前核心"这个
// 事实的只有 start（装载）与 stop（取下即停），installCore 另外供测试注入零值核心。
func (s *session) installCore(core *runner.Core) { s.core.Store(core) }

// startupWarning 返回本次会话的启动警告快照。start 在 mu 下重置/写入它，因此凡是
// 不与那次 start 同 goroutine 的读者都必须走这里——自更新失败后的恢复流程
// （restartServiceInSequence）与启动就分属不同 goroutine。
func (s *session) startupWarning() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.startupWarn
}

// start 启动一次代理会话。
//
// 它全程持有 mu：托盘的切换、自更新重启与退出路径都在各自的 goroutine 里，Stop
// 还会在启动期间的切换请求里与 Start 交错。
func (s *session) start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// 会话级状态在会话起点重置。过去这一步由 restartService 的整体重建
	// （*a.App = App{...}）顺带完成；重建移除后必须在这里做，否则上一轮的
	// 启动警告会既抑制新一轮的记录（只在 nil 时写入），又被恢复流程重复上报。
	s.startupWarn = nil
	s.tunSkippedForNetwork = false

	// 本次会话的配置快照：它一经发布即不可变，因此可以安全地交给核心
	//（核心持有它并做运行期读取，见 client.Client.cfg），不会被菜单改动。
	sessionCfg := s.app.currentConfig()

	core, err := runCore(sessionCfg)
	if err != nil {
		return err
	}
	s.installCore(core)
	if core.StartupWarn != nil {
		s.startupWarn = core.StartupWarn
		log.Warn("[EASYSS-V3] startup warning", "err", core.StartupWarn)
	}
	gen := coreGen.Add(1)
	// 降级启动（开机时网络未就绪、服务端域名暂不可解析）时为 true。
	domainPending := !canStartTunNow(core)

	if sessionCfg.Local.EnableTun2socks {
		// 在 macOS 和 Linux 非 root 环境下，TUN 通过提权启动（助手进程或以 root
		// 重启）。这里跳过直接创建，以避免 "operation not permitted"。到达该分支
		// 意味着用户请求了系统全局流量但无法获得，因此要告知原因，而不是留下一个
		// 静默未代理的系统。main.go 与 headless 构建共享，所以提示走 appUI。
		if (runtime.GOOS == "darwin" || runtime.GOOS == "linux") && !IsRoot() {
			log.Warn("[EASYSS-V3] tun2socks requires root; skipped (use sudo, or run with system tray for automatic elevation)")
			s.app.notifyTunSkippedNoRoot()
		} else if !domainPending {
			// runner.Run 已确保服务端主机名可解析并预填充了 DNS 缓存
			//（resolveServerDomain），因此 TUN 模式的 DNS 永远不会在服务端域名上死锁。
			s.startTunEngineAtStartup()
		} else {
			// 开机时网络常常尚未就绪，服务端域名还没解析出来。此时照常启用 TUN
			// 会让平台脚本把系统 DNS 指向本机转发服务器，而解析服务端域名又需要
			// 隧道本身（递归）；网络根本没起来时脚本还会因缺默认网关失败。
			// 因此跳过 TUN，并把配置与托盘勾选同步为"未启用"，等网络恢复后由
			// 用户手动开启（届时 canStartTunNow 放行）。
			s.app.updateConfig(func(c *config.ClientConfig) { c.Local.EnableTun2socks = false })
			s.tunSkippedForNetwork = true
			log.Warn("[EASYSS-V3] server domain not resolved yet; tun2socks skipped until the network is ready")
			s.app.notifyTunSkippedNetworkUnready()
		}
	}

	// 核心不再从共享配置里"顺带"看到 TUN 状态（见 client.Client.tunMode）：
	// 在决定完本会话是否真的启用 TUN 之后显式告知一次。取的是调整之后的偏好，
	// 因此与拆分前的语义一致（非 root 跳过时仍为 true，降级跳过时已被置为 false）。
	//
	// 这里重读 currentConfig()（而不是复用上面的 sessionCfg）是刻意的：这次启动
	// 可能正与一次 TUN 开关并发，核心应当拿到最新的意图。若"优化"成
	// SetTunMode(sessionCfg.Local.EnableTun2socks)，并发开关的意图就会被丢掉。
	// Client 的 nil 守卫与托盘路径一致（测试会注入零值核心）。
	if core.Client != nil {
		core.Client.SetTunMode(s.app.currentConfig().Local.EnableTun2socks)
	}

	// 后台统计循环（重新）启动：先停掉上一个循环，再把新通道交给它自己捕获，
	// 这样后续重启不会让旧循环在新通道上 select。
	if s.statsCloser != nil {
		close(s.statsCloser)
	}
	s.statsCloser = make(chan struct{})
	go s.statsLoop(s.statsCloser)

	if sessionCfg.PprofEnabled {
		s.pprofSrv = pprof.StartPprof()
	}

	// 降级启动时，网络恢复后向用户报告一次（仅托盘构建装了 appUI）。
	s.app.watchServerDomainReady(core, gen, domainPending, s.tunSkippedForNetwork)

	return nil
}

// stop 停止核心、TUN 引擎与 pprof 服务器。顺序是硬约束：TUN 依赖核心的本地
// 代理入口，必须先停。它幂等，而且是"取下即停"——每个字段在被取走后即为 nil，
// 因此重复或并发的 Stop 不会二次停止同一个对象，也不需要 stopOnce 那样的一次性状态。
//
// Stop 对 TUN 收尾与"取下核心"共用 tunMu，然后才在锁外等核心停止：
//   - 托盘的 TUN 开关在同一把锁内检查 currentCore()，这里在同一临界区里把核心
//     取下，后到的开关就会看到 nil 并回滚菜单，不会给一个已停止的核心装上新的
//     TUN 引擎；
//   - 先到的开关留下的 tunMgr 由这里收走并停止，不会泄漏（它的分流路由留在
//     路由表里就是"全机断网"，见 tunDown 的注释）；
//   - core.Stop() 可能等待在飞中继结束，放在锁外才不会挡住 TUN 开关。
func (s *session) stop() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.statsCloser != nil {
		close(s.statsCloser)
		s.statsCloser = nil
	}

	s.tunMu.Lock()
	if mgr := s.tunMgr; mgr != nil {
		s.tunMgr = nil
		mgr.Stop()
	}
	core := s.core.Swap(nil)
	s.tunMu.Unlock()

	if core != nil {
		core.Stop()
	}
	if srv := s.pprofSrv; srv != nil {
		s.pprofSrv = nil
		pprof.StopPprof(srv)
	}
}

// startTunEngineAtStartup 在启动路径上创建 TUN 管理器并派发引擎启动。
// 构造顺序与托盘菜单路径（session.tunUp）保持一致。调用方持有 mu。
func (s *session) startTunEngineAtStartup() {
	core := s.currentCore()
	if core == nil || core.Client == nil {
		return
	}

	// 与托盘开关路径（session.tunUp）共用 tunMu：两者写的是同一个 tunMgr，
	// 而托盘的菜单在 start 之前就已经可见，点击与启动期创建会并发。
	s.tunMu.Lock()
	defer s.tunMu.Unlock()

	s.tunMgr = tun.New(s.tunConfig())
	s.buildICMPHandler(core)
	s.startTunEngine(s.tunMgr, "device")
}

// tunUp 启用一次 TUN 会话（直接创建设备的路径：Windows，或 darwin/linux 上的
// root）。调用方是托盘菜单（headless 与 --disable-tray 构建没有运行期开关）。
//
// 它全程持有 tunMu：托盘的每一次点击都在自己的 goroutine 里，启用与关闭会并发
// 执行，而它们写的是同一组字段（tunMgr/tunSession/tunHelperStdin）。
func (s *session) tunUp() error {
	s.tunMu.Lock()
	defer s.tunMu.Unlock()

	if s.tunMgr != nil {
		return nil
	}

	// core 检查必须早于任何状态写入：如果这里已经留下了 tunMgr，后续每次点击
	// 都会命中顶部的"已设置"保护而静默返回 nil（菜单勾选着，引擎却从未运行、
	// 也再没人能 Stop 它）。
	core := s.currentCore()
	if core == nil || core.Client == nil {
		return fmt.Errorf("client not initialized")
	}
	// VPN 以 relay_only=false 运行时，对端的直连报文会被 TUN 捕获并绕回 easyss
	// 自己的 SOCKS5（见 runner.Core.CheckVPNTunCompat）。
	// 这个强制只在 tailcat 建 socket 之前有效，因此运行期发现时只能拒绝。
	if err := core.CheckVPNTunCompat(); err != nil {
		return err
	}

	// 偏好（下次启动用）与运行期状态（直连拨号路径用）分别落位：前者走
	// 不可变快照，后者是 core 上的显式开关（见 client.Client.SetTunMode）。
	s.app.updateConfig(func(c *config.ClientConfig) { c.Local.EnableTun2socks = true })
	core.Client.SetTunMode(true)
	s.tunMgr = tun.New(s.tunConfig())
	dev := s.tunMgr.DeviceConfig()
	s.tunSession = &dev

	s.buildICMPHandler(core)
	s.startTunEngine(s.tunMgr, "device")

	return nil
}

// buildICMPHandler 为一次新的 TUN 会话装配 ICMP 处理器。
func (s *session) buildICMPHandler(core *runner.Core) {
	icmpHandler := tun.NewICMPHandler(core.Client.Router())
	icmpHandler.SetProxy(core.StreamHandler, s.app.methodFromServer())
	s.tunMgr.SetICMPHandler(icmpHandler)
}

// tunDown 关闭当前 TUN 会话并撤销它对系统做的改动。
//
// 步骤顺序是硬约束（见每一步的注释），因此它同时被托盘开关、切换服务器前的拆除
// 与 TUN 启动失败的回滚复用。
func (s *session) tunDown() error {
	s.tunMu.Lock()
	defer s.tunMu.Unlock()
	return s.tunDownLocked(nil)
}

// tunDownLocked 是拆除本体，调用方持有 tunMu。want 非 nil 时要求它仍是当前会话的
// 引擎，否则什么都不做：只有迟到的失败回调会这样调用（见 rollbackFailedTunStart），
// 它针对的会话已经被替换，拆除后来者就是拆掉用户刚打开的那个 TUN。
func (s *session) tunDownLocked(want *tun.Manager) error {
	if want != nil && s.tunMgr != want {
		return nil
	}

	// 会话配置必须在清空 tunMgr 之前取下来：它既用于校验，也用于兜底回滚。
	dev := s.tunSession
	if dev == nil && s.tunMgr != nil {
		snapshot := s.tunMgr.DeviceConfig()
		dev = &snapshot
	}
	s.tunSession = nil

	// 1. 先停止 tun2socks 引擎：它会关闭助手进程传给本进程的 TUN fd。
	//    助手进程的关闭脚本会删除该接口，而 iproute2 无法删除仍附着在
	//    fd 上的设备 —— 会报 "device or resource busy" 并把接口留下来，
	//    连同所有 TUN 路由（它们都绑定在该接口上）。此后流量仍会进入
	//    一个无人读取的设备，表现为 TUN 停止后"网络不可用"。
	if s.tunMgr != nil {
		log.Info("[SYSTRAY] tunDown: stopping tun2socks engine")
		s.tunMgr.Stop()
		s.tunMgr = nil
	}

	// 2. 通过关闭 FIFO 通知助手进程退出。
	//    助手进程检测到 stdin 上的 EOF 后清理路由/DNS 并退出。
	//    FIFO 文件本身在 tunHelperStdin 关闭时被删除（见 fifoWriter.Close）。
	helperSignalled := false
	if s.tunHelperStdin != nil {
		log.Info("[SYSTRAY] tunDown: closing helper FIFO")
		s.tunHelperStdin.Close() //nolint:errcheck
		s.tunHelperStdin = nil
		helperSignalled = true
	}

	// 3. 等助手进程退出并复核系统路由表（仅 darwin/linux 的提权路径；其他
	//    平台与 headless 构建上是空实现）。
	if dev != nil {
		if err := s.verifyTeardown(*dev, helperSignalled); err != nil {
			log.Error("[SYSTRAY] tunDown: TUN teardown left routes behind", "err", err)
			s.app.notifyTunTeardownProblem(
				"TUN 已停止，但系统路由表里仍残留指向 TUN 的路由，本机可能无法上网。请退出并重新启动 Easyss，或重启系统以恢复网络。详情：" + err.Error())
		}
	}

	// 4. 清除 HTTP /tun 配置。
	if core := s.currentCore(); core != nil && core.HTTPServer != nil {
		core.HTTPServer.ClearTunConfig()
	}

	// 5. 关掉运行期的 TUN 状态与持久化偏好（两者过去是同一个共享字段）。
	if core := s.currentCore(); core != nil && core.Client != nil {
		core.Client.SetTunMode(false)
	}
	s.app.updateConfig(func(c *config.ClientConfig) { c.Local.EnableTun2socks = false })
	return nil
}

// tunConfig 为一次 TUN 会话构建配置。它是启动路径与托盘开关共享的唯一构造点，
// 因此两者不会出现偏差（尤其是 server-IPv6 提示，托盘路径过去常常遗漏它）。
func (s *session) tunConfig() tun.Config {
	core := s.currentCore()
	if core != nil && core.Client != nil {
		// 降级启动（开机时网络未就绪）会让启动期的 IPv6 解析得到空值；这里在
		// 读取前补一次有界解析，否则 TUN 脚本不会安装 IPv6 默认路由，
		// IPv6 流量会绕过隧道。已有值时该方法直接返回，不做 DNS 查询。
		//
		// 它同时可能触发一次新的 DNS 探测（resolveServerIPV6 会记录可达的内置/
		// 系统解析器），因此必须在 tunDNS 之前执行：在"此前所有标记尝试都失败、
		// 恰好这次刷新才成功"的边角情形下，先取 DNS 会让 TUN 拿到默认值而不是
		// 刚学到的可达服务器。
		core.Client.RefreshServerIPV6()
	}

	// 一次快照供下面两个字段使用：它们必须来自同一份配置（见 currentConfig）。
	snap := s.app.currentConfig()
	cfg := tun.Config{
		Socks5Addr: util.Socks5URI(snap.Local.SocksPort),
		DNSServer:  tunDNS(),
		// MTU 来自唯一的配置旋钮（TunMTU() 已归一化）：它同时决定设备的
		// 真实 MTU 与 netstack 的 MTU，两条路径必须拿到同一个值。
		MTU: snap.TunMTU(),
	}
	if core != nil && core.Client != nil {
		if ipv6 := core.Client.Router().ServerIPV6(); ipv6 != "" {
			cfg.ServerIPV6 = ipv6
		}
	}
	return cfg
}

// startTunEngine 在后台启动 tun2socks 引擎。Manager.Start
// 会阻塞至设备设置、稳定等待延迟和平台路由脚本完成（最长 60 秒），
// 因此不能放在调用方 goroutine 上运行。
//
// 在后台运行还有第二个理由：Stop() 会取消进行中的 Start()（见 tun.Manager），
// 因此"关闭开关/切换服务器/退出应用"必须能在启动还在飞的时候到达 —— 把 Start
// 放进任何单一 mutator goroutine 都会让这条取消路径失去意义。
//
// 上游把启动失败作为错误返回，而不是像过去那样用 log.Fatalf 杀死进程
// （tun2socks #550/#552），因此半启用状态必须由其持有者撤销：失败时回滚界面
// 状态（菜单勾选、已建立的 helper 会话）并向用户说明原因，见 appUI.tunStartFailed。
func (s *session) startTunEngine(mgr *tun.Manager, mode string) {
	go func() {
		if err := mgr.Start(); err != nil {
			log.Error("[EASYSS-V3] tun2socks start", "mode", mode, "err", err)
			s.rollbackFailedTunStart(mgr, err)
		}
	}()
}

// rollbackFailedTunStart 回滚一次失败的 TUN 启动：拆掉那次会话，再让界面复原菜单
// 勾选并说明原因。
//
// "核对身份 → 拆除"必须在同一个 tunMu 临界区内完成，因为这条回调可能迟到：
// tunDown 会取消在飞的 Start（tun.Manager.Stop 等它返回），而那个 goroutine 要等
// Start 返回之后才走到这里；这期间用户完全可能已经重新打开了 TUN（或换了服务器
// 又重新打开），此时会话里已经是另一个引擎。按引擎身份过滤后，迟到的回调只留下
// 一条"已忽略"的日志：它既不会拆掉刚建立的新会话，也不会清掉新会话的启用偏好，
// 更不会把菜单勾选取消成与实际状态不符。
//
// 界面部分放在锁外做：托盘会去改菜单项并弹系统通知，不该在持有 tunMu 时调用。
func (s *session) rollbackFailedTunStart(mgr *tun.Manager, err error) {
	s.tunMu.Lock()
	if s.tunMgr != mgr {
		s.tunMu.Unlock()
		log.Info("[EASYSS-V3] tun2socks start failure ignored: its session has been replaced", "err", err)
		return
	}
	if downErr := s.tunDownLocked(mgr); downErr != nil {
		log.Error("[EASYSS-V3] tun2socks rollback after start failure", "err", downErr)
	}
	s.tunMu.Unlock()

	if s.app.ui != nil {
		s.app.ui.tunStartFailed(err)
	}
}

func (s *session) statsLoop(done <-chan struct{}) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.logStatsOnce()
		case <-done:
			return
		}
	}
}

// logStatsOnce 输出一份统计快照。核心在读取前一次性取快照：它可能在这次
// tick 与 Stop/切换之间被清空或替换，分两次读会读到 nil。
func (s *session) logStatsOnce() {
	core := s.currentCore()
	if core == nil || core.Client == nil {
		return
	}
	snap := stats.Collect()
	snap.TransportStats = core.Client.Transport().Stats()
	log.Info("[STATS]",
		"uptime", snap.Uptime().Round(time.Second),
		"conns", snap.Conns,
		"priority_conns", snap.PriorityConns,
		"bulk_conns", snap.BulkConns,
		"priority_conns_status", snap.PriorityConnsStatus,
		"bulk_conns_status", snap.BulkConnsStatus,
		"active_streams", snap.ActiveStreams,
		"priority_active", snap.PriorityActiveStreams,
		"bulk_active", snap.BulkActiveStreams,
		"streams(opened)", snap.TotalStreamsOpened,
		"streams(closed)", snap.TotalStreamsClosed,
		"priority_opened", snap.PriorityStreamsOpened,
		"bulk_opened", snap.BulkStreamsOpened,
		"priority_fallback", snap.PriorityFallback,
		"bulk_fallback", snap.BulkFallback,
		"tx", stats.HumanBytes(snap.BytesSent),
		"rx", stats.HumanBytes(snap.BytesRecv),
		"raw_tx", stats.HumanBytes(snap.RawBytesSent),
		"raw_rx", stats.HumanBytes(snap.RawBytesRecv),
		"upload_speed", snap.UploadSpeedHuman,
		"download_speed", snap.DownloadSpeedHuman,
		"proxy_tcp_streams", snap.TCPConnections,
		"udp_assoc", snap.UDPAssociations,
		"dns(hit)", snap.DNSCacheHits,
		"dns(miss)", snap.DNSCacheMisses,
		"dns(proxy)", snap.DNSProxyQueries,
		"dns(direct)", snap.DNSDirectQueries,
		"padding", stats.HumanBytes(snap.PaddingBytes),
		"records", snap.RecordsWritten,
		"avg_rtt", snap.AvgRTT().Round(time.Millisecond),
		"slot_degraded", snap.SlotDegraded,
		"slot_retired_degraded", snap.SlotRetiredDegraded,
		"slot_probes", snap.SlotProbes,
		"slot_probe_slow", snap.SlotProbeSlow,
		"slot_grown_priority", snap.SlotGrownPriority,
		"slot_grown_bulk", snap.SlotGrownBulk,
		"conn_rotated", snap.ConnRotated,
	)
}
