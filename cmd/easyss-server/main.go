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
	var cmdConfig easyss.Config

	flag.BoolVar(&printVer, "version", false, "print version")
	flag.StringVar(&configFile, "c", "config.json", "specify config file")
	flag.StringVar(&cmdConfig.Password, "k", "", "password")
	flag.StringVar(&cmdConfig.Server, "s", "", "server address")
	flag.IntVar(&cmdConfig.ServerPort, "p", 0, "server port")
	flag.IntVar(&cmdConfig.Timeout, "t", 30, "timeout in seconds")
	flag.StringVar(&cmdConfig.Method, "m", "", "encryption method, default: aes-256-gcm")
	flag.StringVar(&logLevel, "log-level", "info", "set the log-level(debug, info, warn, error), default: info")

	flag.Parse()

	if printVer {
		easyss.PrintVersion()
		os.Exit(0)
	}

	log.Infof("set the log-level to: %v", logLevel)
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
		log.Debugf("config file err:%v", err)

		binDir := util.CurrentDir()
		configFile = path.Join(binDir, "config.json")

		log.Debugf("config file not found, try config file %s", configFile)
	}

	config, err := easyss.ParseConfig(configFile)
	if err != nil {
		config = &cmdConfig
		if !os.IsNotExist(errors.Cause(err)) {
			log.Errorf("error reading %s: %+v", configFile, err)
			os.Exit(1)
		}
	} else {
		easyss.UpdateConfig(config, &cmdConfig)
	}

	if config.ServerPort == 0 || config.Password == "" || config.Server == "" {
		log.Fatalln("server, port and password should not empty")
	}

	ss, err := easyss.New(config)
	if err != nil {
		log.Errorf("new easyss server err:%v", err)
	}
	ss.Remote()
}
