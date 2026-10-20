package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"syscall"
	_ "time/tzdata"

	"github.com/nange/easyss/v3/client/config"
	easydns "github.com/nange/easyss/v3/client/dns"
	sharedconfig "github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/protocol"
	"github.com/nange/easyss/v3/runner"
	"github.com/nange/easyss/v3/selfupdate"
	"github.com/nange/easyss/v3/util"
	"github.com/nange/easyss/v3/version"
)

func main() {
	// "selfupdate" 和 "tun-helper" 子命令在 flag 解析之前处理，
	// 这样它们永远不会与代理参数冲突。selfupdate 会替换当前运行的二进制并退出；
	// tun-helper 则以提权 TUN 助手模式运行本二进制（由托盘进程内部拉起）并退出。
	if runSelfupdateSubcommand() {
		return
	}
	if runTunHelperSubcommand() {
		return
	}

	var printVer, showConfigExample, showConfigExampleSimple, daemon, disableTray, enableTun2socks bool
	var configFile, cmdOutboundProto string
	var pprofEnabled bool
	var logFile string

	sc := &sharedconfig.SimpleConfig{}

	flag.BoolVar(&printVer, "version", false, "print version")
	flag.BoolVar(&showConfigExample, "show-config-example", false, "show a example of config file (full mode)")
	flag.BoolVar(&showConfigExampleSimple, "show-config-example-simple", false, "show a example of config file (simple mode)")
	flag.StringVar(&sc.Server, "s", "", "server host (domain or IP, without port)")
	flag.IntVar(&sc.ServerPort, "p", 0, "server port")
	flag.StringVar(&sc.Password, "k", "", "password")
	flag.StringVar(&sc.Method, "m", "", "encryption method (aes-256-gcm, chacha20-poly1305)")
	flag.StringVar(&sc.ProxyRule, "proxy-rule", "", "proxy rule (auto, reverse_auto, proxy, direct, auto_block)")
	flag.StringVar(&cmdOutboundProto, "outbound-proto", "", "outbound protocol (native, h2)")
	flag.IntVar(&sc.LocalPort, "l", 0, "local socks5 port")
	flag.IntVar(&sc.Timeout, "t", 0, "timeout in seconds (clamped to 15-60, the base of all derived timeouts)")
	flag.StringVar(&sc.LogLevel, "log-level", "", "log level (debug, info, warn, error)")
	flag.StringVar(&logFile, "log-file", "", "log file path")
	flag.BoolVar(&sc.EnableQUIC, "enable-quic", false, "enable QUIC protocol")
	flag.StringVar(&sc.SN, "sn", "", "TLS SNI override")
	flag.StringVar(&configFile, "c", "config.json", "specify config file")
	flag.BoolVar(&daemon, "daemon", runtime.GOOS != "windows", "run app as daemon")
	flag.BoolVar(&disableTray, "disable-tray", false, "disable system tray (windows/mac only)")
	flag.BoolVar(&enableTun2socks, "enable-tun2socks", false, "enable tun2socks model")
	flag.StringVar(&sc.IPV6Rule, "ipv6-rule", "", "set the ipv6 rule(auto, enable, disable), default: auto")
	flag.StringVar(&sc.DirectFile, "direct-file", "", "custom direct file (IPs/CIDRs/domains/regexps mixed, one per line; supports regexp: prefix and * glob)")
	flag.StringVar(&sc.ProxyFile, "proxy-file", "", "custom proxy file (IPs/CIDRs/domains/regexps mixed, one per line; supports regexp: prefix and * glob)")
	flag.BoolVar(&pprofEnabled, "pprof", false, "enable pprof debug server on :6060")

	// 自定义 usage，使 --help/-h 也能介绍 "selfupdate" 和 "tun-helper"
	// 子命令——它们在 flag 解析之前处理，否则在帮助中不可见。
	flag.Usage = func() {
		bin := filepath.Base(os.Args[0])
		out := flag.CommandLine.Output()
		_, _ = fmt.Fprintf(out, `Easyss - SOCKS5/HTTP 代理客户端

用法:
  %s [flags]              启动代理（托盘版默认带系统托盘，可用 --disable-tray 关闭）
  %s selfupdate [flags]   检查并升级到最新 release
  %s tun-helper [flags]   内部：以提权 TUN 助手模式运行（由主程序自动拉起）

子命令:
  selfupdate    从 GitHub 检查最新 release，并原地替换当前二进制（不自动重启）。
                更新完成后请手动重启进程使新版本生效。支持 --check（仅检查）、
                --version <tag>（安装指定版本，可重装当前版本或回退，tag 需与
                release tag 完全一致）、--proxy-port（走本地代理下载）。
  tun-helper    内部子命令：打开 TUN 设备、配置路由/DNS 并把 fd 传回主进程，
                由主程序在提权场景下自动拉起，请勿手动使用。支持
                --tun-http-addr/--tun-fd-socket/--log-file/--log-level。

Flags:
`, bin, bin, bin)
		flag.PrintDefaults()
	}

	flag.Parse()

	if printVer {
		version.Print()
		os.Exit(0)
	}
	if showConfigExample {
		fmt.Println(exampleV3Config())
		os.Exit(0)
	}
	if showConfigExampleSimple {
		fmt.Println(exampleSimpleConfig())
		os.Exit(0)
	}

	// 在 macOS 上应用常由 Finder/launchd 以 cwd=/ 启动，
	// 因此相对配置文件路径会先在工作目录查找，再回退到可执行文件所在目录。
	configFile = util.ResolvePath(configFile)

	cfg, err := config.LoadConfig(configFile)
	if err != nil {
		if sc.Server != "" && sc.Password != "" {
			cfg, err = config.BuildSimpleConfig(sc)
			if err != nil {
				log.Error("[EASYSS-V3] build config from args", "err", err)
				if !disableTray {
					notifyConfigError(err)
				}
				os.Exit(1)
			}
		} else {
			log.Error("[EASYSS-V3] load config", "err", err)
			if !disableTray {
				notifyConfigError(err)
			}
			os.Exit(1)
		}
	} else if err := config.ApplySimpleOverrides(cfg, sc); err != nil {
		// 命令行覆盖同样要过加载期那套校验（例如 -s 里带了端口）。
		log.Error("[EASYSS-V3] apply simple overrides", "err", err)
		if !disableTray {
			notifyConfigError(err)
		}
		os.Exit(1)
	}

	// 将相对文件路径（direct_file/proxy_file/ca_path）相对于可执行文件目录解析，
	// 这样 macOS Finder/launchd 启动（cwd=/）时仍能找到放在二进制/.app 包旁边的文件。
	cfg.ResolveFilePaths()

	if cfg.Log.FilePath != "" && !filepath.IsAbs(cfg.Log.FilePath) {
		if dir := util.CurrentDir(); dir != "" {
			cfg.Log.FilePath = filepath.Join(dir, cfg.Log.FilePath)
		}
	}

	log.Info("[EASYSS-V3] set log-level", "level", cfg.Log.Level)
	log.Init(cfg.Log.FilePath, cfg.Log.Level)
	log.Info("[EASYSS-V3] " + version.String())

	// 清理上次自更新遗留的文件（为 Windows/macOS 保留的重命名旧二进制、过期的暂存目录）。
	// 在 log.Init 之后执行，这样其日志会写入配置的输出，而不是默认的 stdout 处理器
	//（GUI 构建中 stdout 不可见）。
	selfupdate.CleanupOld()

	// 将配置文件路径改为绝对路径，这样任何提权助手进程
	// 无论工作目录如何都能找到它。
	if !filepath.IsAbs(configFile) {
		if abs, err := filepath.Abs(configFile); err == nil {
			configFile = abs
		}
	}

	if enableTun2socks {
		cfg.Local.EnableTun2socks = true
	}
	if cmdOutboundProto != "" {
		proto, err := config.OutboundProtoToProtocol(cmdOutboundProto)
		if err != nil {
			log.Error("[EASYSS-V3] invalid outbound-proto", "value", cmdOutboundProto, "err", err)
			os.Exit(1)
		}
		cfg.Transport.Protocol = proto
	}
	if pprofEnabled {
		cfg.PprofEnabled = true
	}

	log.Info("[EASYSS-V3] config loaded",
		"config_file", configFile,
		"server", cfg.DefaultServerAddr(),
		"socks_port", cfg.Local.SocksPort,
		"http_port", cfg.Local.HTTPPort,
		"proxy_rule", cfg.Routing.ProxyRule,
		"ipv6_rule", cfg.Routing.IPV6Rule,
		"timeout", cfg.Timeout,
		"conn_lifetime", cfg.ConnLifetimeDuration(),
		"direct_file", cfg.Routing.DirectFile,
		"proxy_file", cfg.Routing.ProxyFile,
	)

	app := newApp(cfg, configFile)
	runApp(disableTray, daemon, app)
}

func sigWait() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	log.Info("[EASYSS-V3] got signal to exit", "signal", <-c)
}

// appUI 是运行期向用户呈现状态所需的最小界面。它取代了过去四个包级函数变量
// （tunStartFailureHook / tunStartNotify / tunStartErrorText / serverDomainReadyNotify）：
// 那些钩子由托盘在 buildTray 中安装，headless 与 --disable-tray 构建保持 nil，而
// "装了哪几个、谁在什么时候装、没装时哪条分支静默"只能靠通读代码确认。现在它是
// App 上的一个字段：nil 表示没有界面（原因只写日志），托盘构建在 buildTray 里把
// 自己装上去，且早于首次 Start——因此引擎 goroutine 与它之间天然有 happens-before。
type appUI interface {
	// tunStartFailed 处理一次 TUN 引擎启动失败：会话已经由
	// session.rollbackFailedTunStart 按引擎身份拆除，界面只需把自己的状态改回去
	//（菜单勾选）并按需说明原因。
	tunStartFailed(err error)
	// notify 呈现一条面向用户的消息（系统通知，尽力而为）。
	notify(msg string)
	// serverDomainReady 报告后台重试已解析出服务端域名、代理恢复可用。
	serverDomainReady(msg string)
	// browserProxyEnabled 报告"系统代理"菜单当前是否勾选。headless 没有菜单，
	// 因此实现必须返回 false。
	browserProxyEnabled() bool
	// setTunMenuChecked 把 TUN 菜单勾选同步到指定状态；没有菜单时为空操作。
	setTunMenuChecked(checked bool)
}

type App struct {
	// cfg 是当前配置快照。它一经发布即视为不可变：菜单改动走 updateConfig
	//（克隆 → 改 → CAS 交换），启动/切换把快照交给新会话，运行中的会话持有
	// 自己那一份。过去它是"共享可变对象"，菜单的原地写与切换的 Clone、以及
	// 运行中核心的运行期读（client.dialAddr 每拨号一次）互相竞争——那正是
	// 拆分它的原因。
	cfg        atomic.Pointer[config.ClientConfig]
	configFile string // 配置文件绝对路径

	// ui 是运行期界面（见 appUI）。托盘在 buildTray 中安装自己；headless 与
	// --disable-tray 构建保持 nil，此时原因只写日志。
	ui appUI

	// sysProxyApplied 记录本进程是否成功改过系统代理。系统代理的 apply/revert
	// 现在归 App 所有：托盘菜单、headless 启动与 App.Stop 都通过它判断是否需要
	// 撤销，避免"菜单勾选状态"和实际系统状态各说各话。
	sysProxyApplied atomic.Bool

	// sess 持有本次会话的全部可变状态与它自己的锁：核心、TUN 引擎、pprof
	// 服务器、后台统计循环与会话级标量。App 上不再有任何会话锁字段——改写
	// 会话只能通过 session 的方法（锁序见 session.go）。
	sess *session
}

// coreGen 为每次会话启动的核心分配单调递增的序号，供后台 goroutine 判断自己
// 观察的核心是否仍是当前核心。它留在包级：序号只要求进程内单调，而 App 的
// 生命周期（包括测试中新建的实例）都共用同一个计数器。
var coreGen atomic.Uint64

// currentCore 返回当前核心的快照；nil 表示没有会话在运行。
func (a *App) currentCore() *runner.Core { return a.sess.currentCore() }

// currentStartupWarn 返回本次会话的启动警告快照。它由 session.start 在锁内
// 重置/写入，因此凡是不与那次 start 同 goroutine 的读者都必须走这里——自更新
// 失败后的恢复流程（restartServiceInSequence）与启动就分属不同 goroutine。
func (a *App) currentStartupWarn() error { return a.sess.startupWarning() }

// newApp 用一个初始配置构造 App：它是 App 持有的第一份不可变快照。
func newApp(cfg *config.ClientConfig, configFile string) *App {
	a := &App{configFile: configFile}
	a.sess = newSession(a)
	a.adoptConfig(cfg)
	return a
}

// currentConfig 返回当前配置快照。快照发布后不可变（见 updateConfig），
// 因此读者无需持锁；需要多个字段时必须先取一次到局部变量，保证它们来自
// 同一份快照（否则可能读到两次发布之间的混合状态）。
func (a *App) currentConfig() *config.ClientConfig { return a.cfg.Load() }

// adoptConfig 整体发布一份新的配置快照。运行期的改动一律走 updateConfig 的
// 增量发布（菜单改动、切换意图都在同一条 CAS 路径上合并），只有 App 的初始
// 配置（newApp）与测试用它整体换装；发布后调用方不得再改写这份快照。
func (a *App) adoptConfig(cfg *config.ClientConfig) { a.cfg.Store(cfg) }

// updateConfig 以 copy-on-write 方式修改当前配置快照：克隆 → 应用 fn →
// CAS 交换；CAS 失败说明有并发发布，带着新克隆重来。fn 因此必须可重复执行
// （只依赖传入的 cfg，不读外部可变状态）。
//
// 它取代了过去的原地改写（`a.cfg.X = v`）：那会让菜单写与切换的 Clone、
// 运行中核心的运行期读构成数据竞争，也会丢失并发更新。
func (a *App) updateConfig(fn func(*config.ClientConfig)) {
	for {
		cur := a.cfg.Load()
		var next *config.ClientConfig
		if cur == nil {
			next = &config.ClientConfig{}
		} else if next = cur.Clone(); next == nil {
			// Clone 是 JSON 往返，理论上只会因不可序列化的字段失败。
			// 此时保留旧快照：把 nil 发布出去会让所有读者解引用它。
			log.Error("[EASYSS-V3] update config: clone failed, keeping the current snapshot")
			return
		}
		fn(next)
		if a.cfg.CompareAndSwap(cur, next) {
			return
		}
	}
}

// runCore 启动一次代理核心。它作为变量（与 restartServiceInSequence 注入 start
// 是同一模式），使测试能注入零值核心来并发驱动真实的 Start/Stop，而不必
// 监听本地端口或连网络。
var runCore = runner.Run

// serverDomainReadiness 是启动路径需要的最小核心视图：服务端域名是否已就绪，
// 以及核心何时停止。抽成接口是为了能在测试中注入假实现
// （*runner.Core 的字段无法从包外构造）。
type serverDomainReadiness interface {
	ServerDomainReady() <-chan struct{}
	Done() <-chan struct{}
}

// canStartTunNow 报告现在是否可以启用 TUN：服务端域名必须已经解析成功
// （或无需解析）。nil core 与未初始化的就绪通道都视为"无需等待"，保持既有行为。
//
// 未就绪时启用 TUN 是危险的：平台脚本会把系统 DNS 指向本机转发服务器，
// 而解析服务端域名又需要先连上服务器（隧道），容易形成解析递归；网络根本
// 没起来时脚本还会因缺默认网关而失败。
func canStartTunNow(core serverDomainReadiness) bool {
	if core == nil {
		return true
	}
	ready := core.ServerDomainReady()
	if ready == nil {
		return true
	}
	select {
	case <-ready:
		return true
	default:
		return false
	}
}

// watchServerDomainReady 在降级启动（服务端域名暂不可解析）后，等待后台重试
// 成功并向用户报告一次。pending 为 false（启动即就绪）时不派发任何 goroutine，
// 否则每次正常启动都会弹一条无意义通知。tunSkipped 由调用方在派发前读取，
// 使 goroutine 不必访问会被下一次启动改写的会话字段。
func (a *App) watchServerDomainReady(core serverDomainReadiness, gen uint64, pending, tunSkipped bool) {
	if !pending || core == nil || a.ui == nil {
		return
	}
	ready, done := core.ServerDomainReady(), core.Done()
	if ready == nil || done == nil {
		return
	}

	go func() {
		select {
		case <-ready:
		case <-done:
			return
		}
		// 就绪与"核心被停止/替换"可能并发发生：过期核心不再弹通知。
		select {
		case <-done:
			return
		default:
		}
		if coreGen.Load() != gen {
			return
		}

		msg := "网络已恢复，代理服务已就绪"
		if tunSkipped {
			msg += "；系统全局流量(Tun2socks)启动时已跳过，可在托盘菜单中重新开启"
		}
		a.ui.serverDomainReady(msg)
	}()
}

// Start 启动一次代理会话。会话状态与它自己的锁都在 session 里（见 session.go）：
// App 上不再有会话锁字段，也没有"调用方持有锁"的契约。
func (a *App) Start() error { return a.sess.start() }

// Stop 停止当前会话：撤销系统代理 → 拆 TUN → 停核心。它与 Close 共同构成
// 三条启动路径与托盘关闭/切换的退出序列；顺序是硬约束（TUN 依赖核心的本地
// 代理入口，必须先拆 TUN）。Stop 幂等，"取下即停"。
func (a *App) Stop() {
	a.teardownSysProxy()

	// 在停止核心服务之前停止 TUN 助手进程和引擎。非 darwin/linux 或 root 下
	// 如果 TUN 不是通过助手进程启动的，tunDown 是空操作。
	if err := a.sess.tunDown(); err != nil {
		log.Error("[EASYSS-V3] stop: close tun2socks", "err", err)
	}

	a.sess.stop()
}

// Close 是托盘的退出/切换序列：与 Stop 的区别是它无条件撤销系统代理，即使
// sysProxyApplied 为假——托盘要清理上一次运行或异步开关留下的、可能指向本地
// 端口的系统代理。headless 与 --disable-tray 不调用它，只撤销自己设置过的代理。
func (a *App) Close() {
	if err := a.setSysProxyOff(); err != nil {
		log.Error("[EASYSS-V3] close: set sysproxy off", "err", err)
	}
	a.Stop()
}

// restartServiceInSequence 是服务器切换的序列体；start 由调用方注入，使测试可以
// 驱动"新服务起不来 → 回滚到旧服务器"这条路径，而不必真的启动代理核心。
//
// newCfg 只是"切换意图"的载体：本函数只从它取目标服务器下标，然后把这**一条
// 增量**应用到当前快照上（见下面的 updateConfig），其余字段一律以当前快照为准。
// 原因是 Close 可能要数秒（macOS 上要等 TUN 拆除的管理员凭据），而序列锁只
// 串行化两套"停/起"，串不住不持锁的菜单路径——若在这里发布一份停服务之前取
// 的全量快照，用户在这期间改的代理规则/日志级别就会被静默还原。
//
// start 收到的配置是"调用时刻生效的快照"，只读（生产实现忽略它，测试据此判断
// 目标服务器与注入失败）。
func (a *App) restartServiceInSequence(newCfg *config.ClientConfig, start func(*config.ClientConfig) error) error {
	targetIdx := newCfg.DefaultServerIndex()

	snap := a.currentConfig()
	prevIdx, prevTun := snap.DefaultServerIndex(), snap.Local.EnableTun2socks

	sysProxyEnabled := a.browserProxyEnabled()

	// 停止一切，包括 TUN。在 macOS 上这会提示输入管理员凭据
	// 以清理路由和 DNS —— 在手动切换服务器期间可以接受。
	a.Close()

	// 停完之后才发布切换意图，且只改这次切换真正要改的两个字段：目标服务器，
	// 以及"切换后 TUN 保持关闭"（托盘菜单与实际状态同步，用户一次点击即可
	// 重新启用）。CAS 发布因此会把停服务期间的菜单改动合并进来，而不是覆盖它。
	a.updateConfig(func(c *config.ClientConfig) {
		c.SetDefaultServerIndex(targetIdx)
		c.Local.EnableTun2socks = false
	})
	a.setTunMenuChecked(false)

	restoreSysProxy := func() {
		if !sysProxyEnabled {
			return
		}
		if err := a.setSysProxyOn(); err != nil {
			log.Error("[EASYSS-V3] restart service: restore sysproxy on", "err", err)
		}
	}

	if err := start(a.currentConfig()); err != nil {
		// 回滚同样只回退这次切换改掉的两个字段（服务器选择与 TUN 偏好），
		// 保留菜单在这期间的最新改动。回滚也失败时两个错误一起上报
		//（调用方据此判断"完全没有服务在运行"）。
		a.updateConfig(func(c *config.ClientConfig) {
			c.SetDefaultServerIndex(prevIdx)
			c.Local.EnableTun2socks = prevTun
		})
		a.setTunMenuChecked(prevTun)
		prevAddr := a.currentConfig().DefaultServerAddr()
		if rollbackErr := start(a.currentConfig()); rollbackErr != nil {
			return errors.Join(err, fmt.Errorf("rollback to %s: %w", prevAddr, rollbackErr))
		}
		log.Warn("[EASYSS-V3] restart service: rolled back to the previous server",
			"addr", prevAddr, "err", err)
		restoreSysProxy()
		return err
	}

	// startupWarn 由 start 里的那次 App.Start（或 buildTray 的初始 Start）写入；
	// 这里的恢复流程与那次 Start 分属不同 goroutine，因此必须走访问器（它读的是
	// 会话自己的锁，见 session.startupWarn）。
	if warn := a.currentStartupWarn(); warn != nil {
		log.Warn("[EASYSS-V3] restart service: startup warning", "err", warn)
	}

	restoreSysProxy()
	return nil
}

// browserProxyEnabled / setTunMenuChecked 把可选界面包装成 nil 安全的方法：
// headless 没有 ui，重启序列只由托盘触发，但 App 本身不应假设 ui 一定存在。
func (a *App) browserProxyEnabled() bool {
	return a.ui != nil && a.ui.browserProxyEnabled()
}

func (a *App) setTunMenuChecked(checked bool) {
	if a.ui != nil {
		a.ui.setTunMenuChecked(checked)
	}
}

// notifyTunSkippedNoRoot 报告 TUN 已配置但因缺少管理员权限而无法启动。
// 提示文本是固定的：没有可附加的底层错误，而且可操作的建议在
// 到达该路径的所有平台上都一样。
func (a *App) notifyTunSkippedNoRoot() {
	a.notifyTunSkipped("Tun2socks 未启用：需要管理员权限，请以 root 运行或使用系统托盘授权")
}

// notifyTunSkippedNetworkUnready 报告 TUN 因服务端域名尚未解析成功而跳过。
func (a *App) notifyTunSkippedNetworkUnready() {
	a.notifyTunSkipped("网络尚未就绪：已跳过系统全局流量(Tun2socks)；网络恢复后请在托盘菜单中重新开启")
}

// notifyTunSkipped 通过界面报告"TUN 被跳过"。没有界面（headless 与
// --disable-tray 构建）时不派发任何东西：原因已由调用方写入日志。
func (a *App) notifyTunSkipped(msg string) {
	if a.ui == nil {
		return
	}
	a.ui.notify(msg)
}

// notifyTunTeardownProblem 报告 TUN 拆除不完整（路由残留且回滚失败）。
// 这是用户必须知道的状态：残留的分流默认路由会把全机流量黑洞掉。
func (a *App) notifyTunTeardownProblem(msg string) {
	if a.ui == nil {
		log.Warn("[EASYSS-V3] notify skipped: no ui", "msg", msg)
		return
	}
	a.ui.notify(msg)
}

// setupSysProxy 按配置把系统代理指向本地 HTTP 代理（见 setSysProxy）。
// 返回 true 表示系统代理已被改动；实际状态同时记入 sysProxyApplied，退出时
// 由 App.Stop 统一撤销。
//
// 配置禁用（disable_sys_proxy）或本地 HTTP 端口无效时它什么都不做；设置失败
// 也只记一条警告：用户仍可手动配置代理，启动不应因此失败——这条降级逻辑
// 对 Linux 上的 root/systemd 场景尤其重要，那里 gsettings 与用户会话总线
// 常常不可达（托盘、--disable-tray 与 headless 三条启动路径共用本函数，
// 避免对 disable_sys_proxy 的处理分叉）。
func (a *App) setupSysProxy() bool {
	cfg := a.currentConfig()
	if cfg.Local.DisableSysProxy || cfg.Local.HTTPPort <= 0 {
		return false
	}
	if err := sysProxyApply(cfg.Local.HTTPPort); err != nil {
		log.Warn("[EASYSS-V3] set system proxy failed, you may need to configure it manually", "err", err)
		return false
	}
	a.sysProxyApplied.Store(true)
	return true
}

// teardownSysProxy 撤销 setupSysProxy/托盘菜单的改动。它只在 sysProxyApplied
// 为真时调用 sysProxyRevert，因此重复 Stop、切换失败回滚与 headless 退出路径
// 可以无脑调用，不会把别人的系统代理设置误撤掉。
func (a *App) teardownSysProxy() {
	if !a.sysProxyApplied.Swap(false) {
		return
	}
	if err := sysProxyRevert(); err != nil {
		log.Warn("[EASYSS-V3] unset system proxy failed, you may need to restore it manually", "err", err)
	}
}

// setSysProxyOn/setSysProxyOff 走 sysProxyApply/sysProxyRevert 这两个包级钩子
// （而不是直接调用实现），使测试可以观察托盘路径上的系统代理改动，而不必触碰
// 运行测试的机器的真实代理配置。两者同时维护 sysProxyApplied，App.Stop 与托盘
// 退出因此共享同一份实际状态。
func (a *App) setSysProxyOn() error {
	err := sysProxyApply(a.currentConfig().Local.HTTPPort)
	if err == nil {
		a.sysProxyApplied.Store(true)
	}
	return err
}

func (a *App) setSysProxyOff() error {
	err := sysProxyRevert()
	if err == nil {
		a.sysProxyApplied.Store(false)
	}
	return err
}

// methodFromServer 返回配置的 AEAD 加密方法；当配置指定了未知方法时
// 回退到 AES-256-GCM。
func (a *App) methodFromServer() protocol.Method {
	method := protocol.MethodFromString(a.currentConfig().DefaultServer().Method)
	if method == 0 {
		method = protocol.MethodAES256GCM
	}
	return method
}

// tunDNS 返回 TUN 模式下需要设置到系统的 DNS 服务器：本会话实测可达的解析器
// （查询作为原始 UDP 通过 TUN 设备发出，由客户端截获后按域名直连/代理拆分）。
// 取值顺序为内置直连 DNS → 系统 DNS（DHCP/内网解析器）→ 内置池第一个 IPv4 项，
// 见 dns.PreferredSystemDNS。
//
// 它与 enable_forward_dns 无关：转发服务器是给 LAN 设备当解析器用的（监听
// 0.0.0.0:53，见 runner.forwardDNSListenAddr），把本机 TUN 的解析器也指向它
// 只会让本机解析绕一圈并丢掉按域名拆分的路径。
func tunDNS() string {
	return easydns.PreferredSystemDNS()
}

func exampleV3Config() string {
	cfg := config.ClientConfig{
		ConfigVersion: 3,
		Servers: []*config.ServerProfile{{
			Host:     "your-domain.com",
			Port:     sharedconfig.DefaultServerPort,
			Password: "your-password",
			Method:   sharedconfig.DefaultMethod,
			SNI:      "",
			CAPath:   "",
			Default:  true,
		}},
		// 示例不走 applyDefaults（不做推导），因此 http_port 按同一规则显式给出。
		Local: config.LocalConfig{
			SocksPort:        sharedconfig.DefaultSocksPort,
			HTTPPort:         sharedconfig.DefaultSocksPort + sharedconfig.DefaultHTTPPortOffset,
			BindAll:          false,
			DisableSysProxy:  false,
			EnableForwardDNS: false,
			EnableTun2socks:  false,
			EnableQUIC:       false,
			TunMTU:           sharedconfig.DefaultTunMTU,
		},
		Routing: config.RoutingConfig{
			ProxyRule:  sharedconfig.DefaultProxyRule,
			IPV6Rule:   sharedconfig.DefaultIPV6Rule,
			DirectFile: "",
			ProxyFile:  "",
		},
		Transport: config.TransportConfig{
			Protocol:          sharedconfig.DefaultProtocol,
			ConnCountMax:      sharedconfig.DefaultConnCountMax,
			StreamThreshold:   sharedconfig.DefaultStreamThreshold,
			PrioritySlotRatio: sharedconfig.DefaultPrioritySlotRatio,
			ConnMaxBytes:      sharedconfig.DefaultConnMaxBytes,
		},
		Shaper: config.ShaperConfig{
			BatchWindowMS:    sharedconfig.DefaultBatchWindowMS,
			CoverBudgetRatio: sharedconfig.DefaultCoverBudgetRatio,
			CoverBudgetCap:   sharedconfig.DefaultCoverBudgetCap,
		},
		Log: config.LogConfig{
			Level:    sharedconfig.DefaultLogLevel,
			FilePath: "easyss.log",
		},
		Timeout:      sharedconfig.DefaultTimeout,
		AuthUsername: "",
		AuthPassword: "",
		PprofEnabled: false,
	}
	b, _ := json.MarshalIndent(cfg, "", "  ")
	return string(b)
}

func exampleSimpleConfig() string {
	cfg := sharedconfig.SimpleConfig{
		Server:        "your-domain.com",
		ServerPort:    sharedconfig.DefaultServerPort,
		Password:      "your-password",
		Method:        sharedconfig.DefaultMethod,
		LocalPort:     sharedconfig.DefaultSocksPort,
		ProxyRule:     sharedconfig.DefaultProxyRule,
		Timeout:       sharedconfig.DefaultTimeout,
		BindAll:       false,
		OutboundProto: "native",
		DirectFile:    "",
		ProxyFile:     "",
		LogLevel:      sharedconfig.DefaultLogLevel,
		LogFilePath:   "easyss.log",
	}
	b, _ := json.MarshalIndent(cfg, "", "  ")
	return string(b)
}
