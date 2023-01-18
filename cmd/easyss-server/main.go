package main

import (
	"flag"
	"os"
	"path"
	"path/filepath"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/nange/easyss"
	"github.com/nange/easyss/util"
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
	var printVer bool
	var cmdConfig easyss.ServerConfig

	flag.BoolVar(&printVer, "version", false, "print version")
	flag.StringVar(&configFile, "c", "config.json", "specify config file")
	flag.StringVar(&cmdConfig.Password, "k", "", "password")
	flag.StringVar(&cmdConfig.Server, "s", "", "server address")
	flag.IntVar(&cmdConfig.ServerPort, "p", 0, "server port")
	flag.StringVar(&logLevel, "log-level", "info", "set the log-level(debug, info, warn, error), default: info")

	flag.Parse()

	if printVer {
		easyss.PrintVersion()
		os.Exit(0)
	}

	log.Infof("[EASYSS_SERVER] set the log-level to: %v", logLevel)
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
		log.Debugf("[EASYSS_SERVER] config file:%v", err)

		binDir := util.CurrentDir()
		configFile = path.Join(binDir, "config.json")

		log.Debugf("[EASYSS_SERVER] config file not found, try config file %s", configFile)
	}

	config, err := easyss.ParseConfig[easyss.ServerConfig](configFile)
	if err != nil {
		config = &cmdConfig
		if !os.IsNotExist(errors.Cause(err)) {
			log.Errorf("[EASYSS_SERVER] error reading %s: %+v", configFile, err)
			os.Exit(1)
		}
	} else {
		easyss.OverrideConfig(config, &cmdConfig)
		config.SetDefaultValue()
	}

	if err := config.Validate(); err != nil {
		log.Fatalf("[EASYSS_SERVER] starts failed, config is invalid:%s", err.Error())
	}

	ss := easyss.NewServer(config)
	ss.Remote()
}
