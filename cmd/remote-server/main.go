package main

import (
	"flag"
	"os"
	"path"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/nange/easyss"
	"github.com/nange/easyss/util"
)

func main() {
	var configFile string
	var printVer, debug bool
	var cmdConfig easyss.Config

	flag.BoolVar(&printVer, "version", false, "print version")
	flag.StringVar(&configFile, "c", "config.json", "specify config file")
	flag.StringVar(&cmdConfig.Password, "k", "", "password")
	flag.StringVar(&cmdConfig.Server, "s", "", "server address")
	flag.IntVar(&cmdConfig.ServerPort, "p", 0, "server port")
	flag.IntVar(&cmdConfig.Timeout, "t", 300, "timeout in seconds")
	flag.StringVar(&cmdConfig.Method, "m", "", "encryption method, default: aes-256-gcm")
	flag.BoolVar(&debug, "d", false, "print debug message")

	flag.Parse()

	if printVer {
		easyss.PrintVersion()
		os.Exit(0)
	}
	if debug {
		log.SetLevel(log.DebugLevel)
	}

	exists, err := util.FileExists(configFile)
	if !exists || err != nil {
		log.Debugf("config file err:%v", err)

		binDir := util.GetCurrentDir()
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

	ss, err := easyss.New(config)
	if err != nil {
		log.Fatalf("init Easyss err:%+v", err)
	}
	if config.ServerPort == 0 || config.Password == "" || config.Server == "" {
		log.Fatalln("server, port and password should not empty")
	}

	ss.Remote()
}
