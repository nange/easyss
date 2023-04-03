package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"syscall"

	"github.com/nange/easyss/v2"
	"github.com/nange/easyss/v2/pprof"
	"github.com/nange/easyss/v2/util"
	"github.com/nange/easyss/v2/version"
	log "github.com/sirupsen/logrus"
)

func init() {
	exec, err := os.Executable()
	if err != nil {
		panic(err)
	}
	logDir := filepath.Dir(exec)
	util.SetLogFileHook(logDir)
}

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
	flag.StringVar(&logLevel, "log-level", "info", "set the log-level(debug, info, warn, error), default: info")
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

	log.Infof("[EASYSS_SERVER_MAIN] set the log-level to: %v", logLevel)
	switch logLevel {
	case "debug":
		log.SetLevel(log.DebugLevel)
	case "warn":
		log.SetLevel(log.WarnLevel)
	case "error":
		log.SetLevel(log.ErrorLevel)
	default:
		log.SetLevel(log.InfoLevel)
	}

	exists, err := util.FileExists(configFile)
	if !exists || err != nil {
		log.Debugf("[EASYSS_SERVER_MAIN] config file:%v", err)

		binDir := util.CurrentDir()
		configFile = path.Join(binDir, "config.json")

		log.Debugf("[EASYSS_SERVER_MAIN] config file not found, try config file %s", configFile)
	}

	config, err := easyss.ParseConfig[easyss.ServerConfig](configFile)
	if err != nil {
		config = &cmdConfig
		if !os.IsNotExist(err) {
			log.Errorf("[EASYSS_SERVER_MAIN] error reading %s: %+v", configFile, err)
			os.Exit(1)
		}
	} else {
		easyss.OverrideConfig(config, &cmdConfig)
		config.SetDefaultValue()
	}

	if err := config.Validate(); err != nil {
		log.Fatalf("[EASYSS_SERVER_MAIN] starts failed, config is invalid:%s", err.Error())
	}

	if enablePprof {
		go pprof.StartPprof()
	}

	ss, err := easyss.NewServer(config)
	if err != nil {
		log.Fatalf("[EASYSS_SERVER_MAIN] new server:%v", err)
	}
	go ss.Start()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGINT, syscall.SIGTERM,
		syscall.SIGQUIT)

	log.Infof("[EASYSS_SERVER_MAIN-SERVER] got signal to exit: %v", <-c)
	if err := ss.Close(); err != nil {
		log.Warnf("[EASYSS_SERVER_MAIN] close easy-server: %v", err)
	}
	os.Exit(0)
}
