package main

import (
	"flag"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"runtime"

	"github.com/nange/easyss/v2"
	"github.com/nange/easyss/v2/pprof"
	"github.com/nange/easyss/v2/util"
	"github.com/nange/easyss/v2/version"
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
	var printVer, daemon, showConfigExample, enablePprof bool
	var cmdConfig easyss.Config

	flag.BoolVar(&printVer, "version", false, "print version")
	flag.BoolVar(&showConfigExample, "show-config-example", false, "show a example of config file")
	flag.StringVar(&cmdConfig.ConfigFile, "c", "config.json", "specify config file")
	flag.StringVar(&cmdConfig.Server, "s", "", "server address")
	flag.StringVar(&cmdConfig.Password, "k", "", "password")
	flag.IntVar(&cmdConfig.ServerPort, "p", 0, "server port")
	flag.IntVar(&cmdConfig.Timeout, "t", 0, "timeout in seconds")
	flag.IntVar(&cmdConfig.LocalPort, "l", 0, "local socks5 proxy port")
	flag.StringVar(&cmdConfig.Method, "m", "", "encryption method, default: aes-256-gcm")
	flag.StringVar(&cmdConfig.LogLevel, "log-level", "", "set the log-level(debug, info, warn, error), default: info")
	flag.StringVar(&cmdConfig.ProxyRule, "proxy-rule", "", "set the proxy rule(auto, reverse_auto, proxy, direct), default: auto")
	flag.BoolVar(&daemon, "daemon", true, "run app as a non-daemon with -daemon=false")
	flag.BoolVar(&cmdConfig.BindALL, "bind-all", false, "listens on all available IPs of the local system. default: false")
	flag.BoolVar(&cmdConfig.EnableForwardDNS, "enable-forward-dns", false, "start a local dns server to forward dns request")
	flag.BoolVar(&cmdConfig.EnableTun2socks, "enable-tun2socks", false, "enable tun2socks model. default: false")
	flag.BoolVar(&cmdConfig.DisableIPV6, "disable-ipv6", true, "disable ipv6 network. default: true")
	flag.BoolVar(&enablePprof, "enable-pprof", false, "enable pprof server. default bind to :6060")

	flag.Parse()

	if printVer || (len(os.Args) > 1 && os.Args[1] == "version") {
		version.Print()
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

	exists, err := util.FileExists(cmdConfig.ConfigFile)
	if !exists || err != nil {
		log.Debugf("[EASYSS-MAIN] config file err:%v", err)

		binDir := util.CurrentDir()
		cmdConfig.ConfigFile = path.Join(binDir, "config.json")

		log.Debugf("[EASYSS-MAIN] config file not found, try config file %s", cmdConfig.ConfigFile)
	}

	config, err := easyss.ParseConfig[easyss.Config](cmdConfig.ConfigFile)
	if err != nil {
		config = &cmdConfig
		if !os.IsNotExist(err) {
			log.Errorf("[EASYSS-MAIN] error reading %s: %+v", cmdConfig.ConfigFile, err)
			os.Exit(1)
		}
	} else {
		easyss.OverrideConfig(config, &cmdConfig)
		config.SetDefaultValue()
	}

	if err := config.Validate(); err != nil {
		log.Fatalf("[EASYSS-MAIN] config is invalid:%s", err.Error())
	}

	log.Infof("[EASYSS-MAIN] set the log-level to: %v", config.LogLevel)
	switch config.LogLevel {
	case "debug":
		log.SetLevel(log.DebugLevel)
	case "warn":
		log.SetLevel(log.WarnLevel)
	case "error":
		log.SetLevel(log.ErrorLevel)
	default:
		log.SetLevel(log.InfoLevel)
	}

	if enablePprof {
		go pprof.StartPprof()
	}

	log.Infof(version.String())

	ss, err := easyss.New(config)
	if err != nil {
		log.Fatalf("[EASYSS-MAIN] init easyss: %v", err)
	}
	Start(ss)
}
