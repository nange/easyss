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

	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/pprof"
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
                --version <tag>（安装指定版本，可重装当前版本或回退，tag 需与
                release tag 完全一致）、--proxy-port（走本地代理下载）。

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

	// 版本校验、默认值（timeout/log.level）与相对文件路径（证书、代理列表、
	// 日志文件）解析都在 config.LoadConfig 内完成（见 server/config/config.go）。
	fileCfg, err := config.LoadConfig(configFile)
	if err != nil {
		log.Error("[EASYSS-SERVER-V3] load config", "err", err, "file", configFile)
		os.Exit(1)
	}
	if pprofEnabled {
		fileCfg.PprofEnabled = true
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

	srv, err := server.New(fileCfg)
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
	b, _ := json.MarshalIndent(config.ExampleConfig(), "", "  ")
	return string(b)
}
