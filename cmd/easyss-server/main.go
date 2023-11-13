package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path"
	"syscall"

	"github.com/nange/easyss/v2"
	"github.com/nange/easyss/v2/log"
	"github.com/nange/easyss/v2/pprof"
	"github.com/nange/easyss/v2/util"
	"github.com/nange/easyss/v2/version"
)

func main() {
	var configFile, logLevel string
	var printVer, showConfigExample, enablePprof bool
	var cmdConfig easyss.ServerConfig

	flag.BoolVar(&printVer, "version", false, "print version")
	flag.BoolVar(&showConfigExample, "show-config-example", false, "show a example of config file")
	flag.StringVar(&configFile, "c", "config.json", "specify config file")
	flag.StringVar(&cmdConfig.Password, "k", "", "password")
	flag.StringVar(&cmdConfig.Server, "s", "", "server address")
	flag.IntVar(&cmdConfig.ServerPort, "p", 0, "server port")
	flag.StringVar(&cmdConfig.LogLevel, "log-level", "", "set the log-level(debug, info, warn, error), default: info")
	flag.StringVar(&cmdConfig.LogFilePath, "log-file-path", "", "set the log output location, default: Stdout")
	flag.StringVar(&cmdConfig.CertPath, "cert-path", "", "set custom Cert file path")
	flag.StringVar(&cmdConfig.KeyPath, "key-path", "", "set custom Key file path")
	flag.BoolVar(&enablePprof, "enable-pprof", false, "enable pprof server. default bind to :6060")

	flag.Parse()

	if printVer || (len(os.Args) > 1 && os.Args[1] == "version") {
		version.Print()
		os.Exit(0)
	}
	if showConfigExample {
		fmt.Printf("%s\n", easyss.ExampleServerJSONConfig())
		os.Exit(0)
	}

	exists, err := util.FileExists(configFile)
	if !exists || err != nil {
		log.Debug("[EASYSS_SERVER_MAIN] config file", "err", err)

		binDir := util.CurrentDir()
		configFile = path.Join(binDir, "config.json")

		log.Debug("[EASYSS_SERVER_MAIN] config file not found, try config file", "file", configFile)
	}

	config, err := easyss.ParseConfig[easyss.ServerConfig](configFile)
	if err != nil {
		config = &cmdConfig
		if !os.IsNotExist(err) {
			log.Error("[EASYSS_SERVER_MAIN] reading", "file", configFile, "err", err)
			os.Exit(1)
		}
	} else {
		easyss.OverrideConfig(config, &cmdConfig)
	}
	config.SetDefaultValue()

	if err := config.Validate(); err != nil {
		log.Error("[EASYSS_SERVER_MAIN] starts failed, config is invalid", "err", err)
		os.Exit(1)
	}

	log.Info("[EASYSS_SERVER_MAIN] set the log-level to", "level", logLevel)
	log.Init(config.GetLogFilePath(), config.LogLevel)

	if enablePprof {
		go pprof.StartPprof()
	}

	ss, err := easyss.NewServer(config)
	if err != nil {
		log.Error("[EASYSS_SERVER_MAIN] new server", "err", err)
		os.Exit(1)
	}
	go ss.Start()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGINT, syscall.SIGTERM,
		syscall.SIGQUIT)

	log.Info("[EASYSS_SERVER_MAIN-SERVER] got signal to exit", "signal", <-c)
	if err := ss.Close(); err != nil {
		log.Warn("[EASYSS_SERVER_MAIN] close easy-server", "err", err)
	}
	os.Exit(0)
}
