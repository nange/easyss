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
	"github.com/nange/easyss/v3/cmd/easyss/internal/vpncmd"
	"github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/selfupdate"
	"github.com/nange/easyss/v3/util"
	"github.com/nange/easyss/v3/version"
)

func main() {
	// "selfupdate"、"tun-helper" 与 "vpn" 必须在 flag 解析前分流，否则参数会与代理参数冲突。
	if selfupdatecmd.Run() {
		return
	}
	if tunhelper.RunSubcommand() {
		return
	}
	if vpncmd.Run() {
		return
	}

	var printVer, showConfigExample, showConfigExampleSimple, daemon, disableTray, enableTun2socks bool
	var configFile, cmdOutboundProto string
	var pprofEnabled bool
	var logFile string

	sc := &config.SimpleConfig{}

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

	flag.Usage = func() {
		bin := filepath.Base(os.Args[0])
		out := flag.CommandLine.Output()
		_, _ = fmt.Fprintf(out, `Easyss - SOCKS5/HTTP 代理客户端

用法:
  %s [flags]              启动代理（托盘版默认带系统托盘，可用 --disable-tray 关闭）
  %s selfupdate [flags]   检查并升级到最新 release
  %s vpn <subcommand>     节点组网(VPN)：打印或重新生成本机身份（详见 %s vpn -h）
  %s tun-helper [flags]   内部：以提权 TUN 助手模式运行（由主程序自动拉起）

子命令:
  selfupdate    从 GitHub 检查最新 release，并原地替换当前二进制（不自动重启）。
                更新完成后请手动重启进程使新版本生效。支持 --check（仅检查）、
                --version <tag>（安装指定版本，可重装当前版本或回退，tag 需与
                release tag 完全一致）、--proxy-port（走本地代理下载）。
  vpn           identity 打印 client nodekey 与节点地址（都要填到对端配置里），
                regen 重新生成身份（被替换的文件备份为 <file>.bak）。
  tun-helper    内部子命令：打开 TUN 设备、配置路由/DNS 并把 fd 传回主进程，
                由主程序在提权场景下自动拉起，请勿手动使用。支持
                --tun-http-addr/--tun-fd-socket/--log-file/--log-level。

Flags:
`, bin, bin, bin, bin, bin)
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

	// 相对路径按可执行文件目录解析，launchd 启动（cwd=/）时才找得到。
	cfg.ResolveFilePaths()

	// VPN 身份的输出与重新生成都在 "vpn" 子命令里（见 vpn_cmd.go），它在 flag 解析
	// 之前就被分派掉了——所以这里不需要"打印完就退出"这类分支，启动路径保持单一。

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
	application.Run(disableTray, daemon)
}
