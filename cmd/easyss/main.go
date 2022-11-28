package main

import (
	"flag"
	"fmt"
	_ "net/http/pprof"
	"os"
	"path"
	"path/filepath"
	"runtime"

	"github.com/nange/easyss"
	"github.com/nange/easyss/util"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

func init() {
	if runtime.GOOS != "android" && runtime.GOOS != "ios" {
		exec, err := os.Executable()
		if err != nil {
			panic(err)
		}
		logDir := filepath.Dir(exec)
		util.SetLogFileHook(logDir)
	}
}

func main() {
	var logLevel string
	var printVer, daemon, showConfigExample bool
	var cmdConfig easyss.Config

	flag.BoolVar(&printVer, "version", false, "print version")
	flag.BoolVar(&showConfigExample, "show-config-example", false, "show a example of config file")
	flag.StringVar(&cmdConfig.ConfigFile, "c", "config.json", "specify config file")
	flag.StringVar(&cmdConfig.Server, "s", "", "server address")
	flag.StringVar(&cmdConfig.Password, "k", "", "password")
	flag.IntVar(&cmdConfig.ServerPort, "p", 0, "server port")
	flag.IntVar(&cmdConfig.Timeout, "t", 30, "timeout in seconds")
	flag.IntVar(&cmdConfig.LocalPort, "l", 0, "local socks5 proxy port")
	flag.StringVar(&cmdConfig.Method, "m", "", "encryption method, default: aes-256-gcm")
	flag.StringVar(&logLevel, "log-level", "info", "set the log-level(debug, info, warn, error), default: info")
	flag.BoolVar(&daemon, "daemon", true, "run app as a non-daemon with -daemon=false")
	flag.BoolVar(&cmdConfig.BindALL, "bind-all", false, "listens on all available IPs of the local system. default: false")
	flag.StringVar(&cmdConfig.Tun2socksModel, "tun2socks-model", "off", "set tun2socks model(off, auto, on). default: off")

	flag.Parse()

	if printVer {
		easyss.PrintVersion()
		os.Exit(0)
	}
	if showConfigExample {
		fmt.Printf("%s\n", easyss.ExampleJSONConfig())
		os.Exit(0)
	}

	if runtime.GOOS != "windows" {
		// starting easyss as daemon only in client model,` and save logs to file`
		easyss.Daemon(daemon)
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

	exists, err := util.FileExists(cmdConfig.ConfigFile)
	if !exists || err != nil {
		log.Debugf("config file err:%v", err)

		binDir := util.CurrentDir()
		cmdConfig.ConfigFile = path.Join(binDir, "config.json")

		log.Debugf("config file not found, try config file %s", cmdConfig.ConfigFile)
	}

	config, err := easyss.ParseConfig(cmdConfig.ConfigFile)
	if err != nil {
		config = &cmdConfig
		if !os.IsNotExist(errors.Cause(err)) {
			log.Errorf("error reading %s: %+v", cmdConfig.ConfigFile, err)
			os.Exit(1)
		}
	} else {
		easyss.UpdateConfig(config, &cmdConfig)
	}

	if config.Password == "" || config.Server == "" || config.ServerPort == 0 {
		log.Fatalln("server address, server port and password should not empty")
	}

	ss, err := easyss.New(config)
	if err != nil {
		log.Errorf("new easyss server err:%v", err)
	}
	StartEasyss(ss)
}
