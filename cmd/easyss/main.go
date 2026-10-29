package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	_ "time/tzdata"

	clientconfig "github.com/nange/easyss/v3/client/config"
	"github.com/nange/easyss/v3/cmd/easyss/internal/app"
	"github.com/nange/easyss/v3/cmd/easyss/internal/selfupdatecmd"
	"github.com/nange/easyss/v3/cmd/easyss/internal/tunhelper"
	"github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/selfupdate"
	"github.com/nange/easyss/v3/util"
	"github.com/nange/easyss/v3/version"
)

func main() {
	// "selfupdate" 与 "tun-helper" 必须在 flag 解析前分流，否则参数会与代理参数冲突。
	if selfupdatecmd.Run() {
		return
	}
	if tunhelper.RunSubcommand() {
		return
	}

	var printVer, showConfigExample, showConfigExampleSimple, daemon, disableTray, enableTun2socks bool
	var restart app.RestartState
	var configFile, cmdOutboundProto string
	var pprofEnabled bool
	var logFile string

	sc := &config.SimpleConfig{}

	flag.BoolVar(&printVer, "version", false, "打印版本信息")
	flag.BoolVar(&showConfigExample, "show-config-example", false, "显示配置示例（完整模式）")
	flag.BoolVar(&showConfigExampleSimple, "show-config-example-simple", false, "显示配置示例（简化模式）")
	flag.StringVar(&sc.Server, "s", "", "服务端地址（域名或 IP，不含端口）")
	flag.IntVar(&sc.ServerPort, "p", 0, "服务端端口")
	flag.StringVar(&sc.Password, "k", "", "密码")
	flag.StringVar(&sc.Method, "m", "", "加密方式（aes-256-gcm、chacha20-poly1305）")
	flag.StringVar(&sc.ProxyRule, "proxy-rule", "", "代理规则（auto、reverse_auto、proxy、direct、auto_block）")
	flag.StringVar(&cmdOutboundProto, "outbound-proto", "", "出站协议（native、h2）")
	flag.IntVar(&sc.LocalPort, "l", 0, "本地 SOCKS5 端口")
	flag.IntVar(&sc.Timeout, "t", 0, "超时秒数（限制在 15-60，所有派生超时的基准）")
	flag.StringVar(&sc.LogLevel, "log-level", "", "日志级别（debug、info、warn、error）")
	flag.StringVar(&logFile, "log-file", "", "日志文件路径")
	flag.BoolVar(&sc.EnableQUIC, "enable-quic", false, "启用 QUIC 协议")
	flag.StringVar(&sc.SN, "sn", "", "覆盖 TLS SNI")
	flag.StringVar(&configFile, "c", "config.json", "指定配置文件")
	flag.BoolVar(&daemon, "daemon", runtime.GOOS != "windows", "以守护进程方式运行")
	flag.BoolVar(&disableTray, "disable-tray", false, "禁用系统托盘（仅 Windows/macOS）")
	flag.BoolVar(&enableTun2socks, "enable-tun2socks", false, "启用 tun2socks 模式")
	flag.Var(&restart, "elevated-restart", "内部参数：以管理员身份接管正在运行的实例")
	flag.StringVar(&sc.IPV6Rule, "ipv6-rule", "", "设置 IPv6 规则（auto、enable、disable），默认 auto")
	flag.StringVar(&sc.DirectFile, "direct-file", "", "自定义直连文件（IP/CIDR/域名/正则混合，每行一条；支持 regexp: 前缀和 * 通配）")
	flag.StringVar(&sc.ProxyFile, "proxy-file", "", "自定义代理文件（IP/CIDR/域名/正则混合，每行一条；支持 regexp: 前缀和 * 通配）")
	flag.BoolVar(&pprofEnabled, "pprof", false, "在 :6060 启动 pprof 调试服务")

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

参数:
`, bin, bin, bin)
		flag.PrintDefaults()
	}

	flag.Parse()

	if printVer {
		version.Print()
		os.Exit(0)
	}
	if showConfigExample {
		b, _ := json.MarshalIndent(clientconfig.ExampleConfig(), "", "  ")
		fmt.Println(string(b))
		os.Exit(0)
	}
	if showConfigExampleSimple {
		b, _ := json.MarshalIndent(clientconfig.ExampleSimpleConfig(), "", "  ")
		fmt.Println(string(b))
		os.Exit(0)
	}

	configFile = util.ResolvePath(configFile)

	cfg, err := clientconfig.LoadConfig(configFile)
	if err != nil {
		if sc.Server != "" && sc.Password != "" {
			cfg, err = clientconfig.BuildSimpleConfig(sc)
			if err != nil {
				log.Error("[EASYSS-V3] build config from args", "err", err)
				if !disableTray {
					app.NotifyConfigError(err)
				}
				os.Exit(1)
			}
		} else {
			log.Error("[EASYSS-V3] load config", "err", err)
			if !disableTray {
				app.NotifyConfigError(err)
			}
			os.Exit(1)
		}
	} else if err := clientconfig.ApplySimpleOverrides(cfg, sc); err != nil {

		log.Error("[EASYSS-V3] apply simple overrides", "err", err)
		if !disableTray {
			app.NotifyConfigError(err)
		}
		os.Exit(1)
	}

	// 提权重启交接过来的运行期选择（服务器/浏览器代理/规则/日志级别）。必须在 log.Init
	// 之前：日志级别只影响本进程，Init 之后再改就没机会了。
	restart.Apply(cfg)

	// 相对路径按可执行文件目录解析，launchd 启动（cwd=/）时才找得到。
	cfg.ResolveFilePaths()

	if cfg.Log.FilePath != "" && !filepath.IsAbs(cfg.Log.FilePath) {
		if dir := util.CurrentDir(); dir != "" {
			cfg.Log.FilePath = filepath.Join(dir, cfg.Log.FilePath)
		}
	}

	log.Info("[EASYSS-V3] set log-level", "level", cfg.Log.Level)
	log.Init(cfg.Log)
	log.Info("[EASYSS-V3] " + version.String())

	// 须在 log.Init 之后，清理日志才写到配置的输出而不是 GUI 中不可见的 stdout。
	selfupdate.CleanupOld()

	// 转成绝对路径，提权助手进程无论 cwd 如何都能找到配置。
	if !filepath.IsAbs(configFile) {
		if abs, err := filepath.Abs(configFile); err == nil {
			configFile = abs
		}
	}

	if enableTun2socks {
		cfg.Local.EnableTun2socks = true
	}
	if cmdOutboundProto != "" {
		proto, err := clientconfig.OutboundProtoToProtocol(cmdOutboundProto)
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

	application := app.New(cfg, configFile)
	application.Run(disableTray, daemon, restart.Enabled())
}
