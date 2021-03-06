package main

import (
	"flag"
	"io"
	"os"
	"path"
	"runtime"

	"github.com/nange/easyss"
	"github.com/nange/easyss/util"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

func main() {
	var configFile string
	var printVer, debug, godaemon bool
	var cmdConfig easyss.Config

	flag.BoolVar(&printVer, "version", false, "print version")
	flag.StringVar(&configFile, "c", "config.json", "specify config file")
	flag.StringVar(&cmdConfig.Server, "s", "", "server address")
	flag.StringVar(&cmdConfig.Password, "k", "", "password")
	flag.IntVar(&cmdConfig.ServerPort, "p", 0, "server port")
	flag.IntVar(&cmdConfig.Timeout, "t", 300, "timeout in seconds")
	flag.IntVar(&cmdConfig.LocalPort, "l", 0, "local socks5 proxy port")
	flag.StringVar(&cmdConfig.Method, "m", "", "encryption method, default: aes-256-gcm")
	flag.BoolVar(&debug, "d", false, "print debug message")
	flag.BoolVar(&godaemon, "daemon", true, "run app as a non-daemon with -daemon=false")

	flag.Parse()

	if printVer {
		easyss.PrintVersion()
		os.Exit(0)
	}
	// we starting easyss as daemon only in client model, and save logs to file
	var writer io.Writer
	if runtime.GOOS != "windows" {
		easyss.Daemon(godaemon)
	}
	var err error
	writer, err = util.GetLogFileWriter(easyss.LogMaxAge, easyss.LogRotationTime)
	if err != nil {
		log.Errorf("get log file output writer err:%v", err)
	} else {
		log.SetOutput(writer)
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
	ss.LogFileWriter = writer
	if config.Password == "" || config.Server == "" || config.ServerPort == 0 {
		log.Fatalln("server address, server port and password should not empty")
	}

	StartEasyss(ss)
}
