package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
	_ "time/tzdata"

	sharedconfig "github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/pprof"
	"github.com/nange/easyss/v3/protocol"
	"github.com/nange/easyss/v3/selfupdate"
	"github.com/nange/easyss/v3/server"
	"github.com/nange/easyss/v3/server/config"
	"github.com/nange/easyss/v3/util"
	"github.com/nange/easyss/v3/version"
)

func main() {
	// "selfupdate" 子命令在解析 flag 之前处理，因此永远不会与服务端参数冲突。
	// 它会替换正在运行的二进制并直接退出，不启动服务端。
	if len(os.Args) > 1 && os.Args[1] == "selfupdate" {
		os.Exit(selfupdate.RunCLICommand(os.Args[2:], selfupdate.ProductServer))
	}

	var printVer, showConfigExample bool
	var configFile string
	var pprofEnabled bool

	flag.BoolVar(&printVer, "version", false, "print version")
	flag.BoolVar(&showConfigExample, "show-config-example", false, "show a example of config file")
	flag.StringVar(&configFile, "c", "config.json", "specify config file")
	flag.BoolVar(&pprofEnabled, "pprof", false, "enable pprof debug server on :6060")

	// 自定义 usage，使 --help/-h 也能介绍 "selfupdate" 子命令；
	// 该子命令在解析 flag 之前处理，否则在帮助里根本看不到。
	flag.Usage = func() {
		bin := filepath.Base(os.Args[0])
		out := flag.CommandLine.Output()
		_, _ = fmt.Fprintf(out, `Easyss Server - 代理服务端

用法:
  %s [flags]              启动服务端
  %s selfupdate [flags]   检查并升级到最新 release

子命令:
  selfupdate    从 GitHub 检查最新 release，并原地替换当前二进制（不自动重启）。
                更新完成后请手动重启进程使新版本生效。支持 --check（仅检查）、
                --proxy-port（走本地代理下载）。

Flags:
`, bin, bin)
		flag.PrintDefaults()
	}

	flag.Parse()

	if printVer {
		version.Print()
		os.Exit(0)
	}
	if showConfigExample {
		fmt.Println(exampleV3ServerConfig())
		os.Exit(0)
	}

	// 在 macOS 上服务端常由 launchd 以 cwd=/ 启动，因此相对配置路径
	// 会先在当前工作目录中查找，再回退到可执行文件所在目录。
	configFile = util.ResolvePath(configFile)

	data, err := os.ReadFile(configFile)
	if err != nil {
		log.Error("[EASYSS-SERVER-V3] read config", "err", err)
		os.Exit(1)
	}

	var fileCfg config.FileConfig
	if err := json.Unmarshal(data, &fileCfg); err != nil {
		log.Error("[EASYSS-SERVER-V3] parse config", "err", err)
		os.Exit(1)
	}
	// 为其他主版本编写的配置可能包含本二进制会静默忽略（或作不同解释）的字段，
	// 因此拒绝基于它启动。0 表示该字段不存在（早于该字段的配置），按未设置处理。
	if fileCfg.ConfigVersion != 0 && fileCfg.ConfigVersion != 3 {
		log.Error("[EASYSS-SERVER-V3] unsupported config version",
			"version", fileCfg.ConfigVersion, "supported", 3, "file", configFile)
		os.Exit(1)
	}
	// 将相对文件路径（cert_path/key_path/next_proxy_file）解析为相对
	// 可执行文件目录的路径，使 macOS launchd（cwd=/）启动时仍能找到
	// 放在二进制旁边的文件。
	fileCfg.ResolveFilePaths()
	if pprofEnabled {
		fileCfg.PprofEnabled = true
	}
	if fileCfg.Log.Level == "" {
		fileCfg.Log.Level = "info"
	}

	// 将相对日志文件路径基于可执行文件目录解析为绝对路径。
	if fileCfg.Log.FilePath != "" && !filepath.IsAbs(fileCfg.Log.FilePath) {
		if dir := util.CurrentDir(); dir != "" {
			fileCfg.Log.FilePath = filepath.Join(dir, fileCfg.Log.FilePath)
		}
	}

	log.Init(fileCfg.Log.FilePath, fileCfg.Log.Level)

	// 清理上一次自更新遗留的残留文件（Windows 上保留的重命名旧二进制
	// 以及过期的暂存目录）。
	selfupdate.CleanupOld()

	log.Info("[EASYSS-SERVER-V3] " + version.String())
	log.Info("[EASYSS-SERVER-V3] config loaded",
		"config_file", configFile,
		"listen", fileCfg.Server.Listen,
		"domain", fileCfg.Server.Domain,
		"next_proxy_file", fileCfg.NextProxy.NextProxyFile,
		"cert", fileCfg.Server.CertPath,
		"key", fileCfg.Server.KeyPath,
	)

	var pprofSrv *http.Server
	if fileCfg.PprofEnabled {
		pprofSrv = pprof.StartPprof()
	}

	srv, err := server.New(&fileCfg)
	if err != nil {
		log.Error("[EASYSS-SERVER-V3] init server", "err", err)
		os.Exit(1)
	}

	startErrCh := make(chan error, 1)
	go func() {
		startErrCh <- srv.Start()
	}()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)

	select {
	case err := <-startErrCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("[EASYSS-SERVER-V3] start server", "err", err)
			os.Exit(1)
		}
	case sig := <-c:
		log.Info("[EASYSS-SERVER-V3] got signal to exit", "signal", sig)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Error("[EASYSS-SERVER-V3] shutdown server", "err", err)
	}
	if pprofSrv != nil {
		pprof.StopPprof(pprofSrv)
	}
	os.Exit(0)
}

func exampleV3ServerConfig() string {
	cfg := config.FileConfig{
		ConfigVersion: 3,
		Server: config.ServerConfig{
			Listen:         ":443",
			Domain:         "your-domain.com",
			Password:       "your-password",
			AllowedMethods: []string{protocol.MethodAES256GCM.String(), protocol.MethodChaCha20Poly1305.String()},
			CertPath:       "",
			KeyPath:        "",
			Email:          "",
		},
		Fallback: config.FallbackConfig{
			Target:       "",
			PreserveHost: false,
			CDNDomains:   []string{},
		},
		Shaper: config.ShaperConfig{
			BatchWindowMS:    sharedconfig.DefaultBatchWindowMS,
			CoverBudgetRatio: sharedconfig.DefaultCoverBudgetRatio,
			CoverBudgetCap:   sharedconfig.DefaultCoverBudgetCap,
		},
		Transport: config.TransportConfig{
			Protocols:       []string{"h2"},
			H2MaxFrameSize:  sharedconfig.HTTP2ServerMaxReadFrameSize,
			H2RecvBufConn:   sharedconfig.HTTP2ServerReceiveBufferPerConnection,
			H2RecvBufStream: sharedconfig.HTTP2ServerReceiveBufferPerStream,
		},
		NextProxy: config.NextProxyConfig{
			URL:           "",
			NextProxyFile: "",
			EnableUDP:     false,
			AllHost:       false,
		},
		Log: config.LogConfig{
			Level:    "info",
			FilePath: "easyss.log",
		},
		PprofEnabled: false,
		Timeout:      30,
	}
	b, _ := json.MarshalIndent(cfg, "", "  ")
	return string(b)
}
