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
	"github.com/nange/easyss/v3/server"
	"github.com/nange/easyss/v3/server/config"
	"github.com/nange/easyss/v3/util"
	"github.com/nange/easyss/v3/version"
)

func main() {
	var printVer, showConfigExample bool
	var configFile string
	var pprofEnabled bool

	flag.BoolVar(&printVer, "version", false, "print version")
	flag.BoolVar(&showConfigExample, "show-config-example", false, "show a example of config file")
	flag.StringVar(&configFile, "c", "config.json", "specify config file")
	flag.BoolVar(&pprofEnabled, "pprof", false, "enable pprof debug server on :6060")

	flag.Parse()

	if printVer {
		version.Print()
		os.Exit(0)
	}
	if showConfigExample {
		fmt.Println(exampleV3ServerConfig())
		os.Exit(0)
	}

	data, err := os.ReadFile(configFile)
	if err != nil {
		log.Error("[EASYSS-SERVER-V3] read config", "err", err)
		os.Exit(1)
	}

	var cfg config.ServerConfig
	var fileCfg config.FileConfig
	if err := json.Unmarshal(data, &fileCfg); err != nil {
		log.Error("[EASYSS-SERVER-V3] parse config", "err", err)
		os.Exit(1)
	}
	cfg = fileCfg.EffectiveServerConfig()
	if pprofEnabled {
		cfg.PprofEnabled = true
	}
	if fileCfg.Log.Level == "" {
		fileCfg.Log.Level = "info"
	}

	// Resolve relative log file path to absolute based on executable directory.
	if fileCfg.Log.FilePath != "" && !filepath.IsAbs(fileCfg.Log.FilePath) {
		if dir := util.CurrentDir(); dir != "" {
			fileCfg.Log.FilePath = filepath.Join(dir, fileCfg.Log.FilePath)
		}
	}

	log.Init(fileCfg.Log.FilePath, fileCfg.Log.Level)

	log.Info("[EASYSS-SERVER-V3] " + version.String())

	var pprofSrv *http.Server
	if cfg.PprofEnabled {
		pprofSrv = pprof.StartPprof()
	}

	srv, err := server.New(&cfg)
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
			Listen:           ":443",
			Domain:           "your-domain.com",
			Password:         "your-password",
			AllowedMethods:   []string{"aes-256-gcm", "chacha20-poly1305"},
			CertPath:         "",
			KeyPath:          "",
			Email:            "your-email@example.com",
			FallbackTarget:   "",
			BatchWindowMS:    3,
			CoverBudgetRatio: 0.02,
			CoverBudgetCap:   128 * 1024,
			PprofEnabled:     false,
		},
		Transport: config.TransportConfig{
			Protocol:       "h2",
			EndpointPrefix: "/v3",
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
		Timeout: 30,
	}
	b, _ := json.MarshalIndent(cfg, "", "  ")
	return string(b)
}
