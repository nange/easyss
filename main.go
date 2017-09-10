package main

import (
	"flag"
	"fmt"
	"os"
	"path"

	"github.com/nange/easyss/utils"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

func init() {
	log.SetFormatter(&log.JSONFormatter{TimestampFormat: "2006-01-02 15:04:05.000"})
	log.SetLevel(log.InfoLevel)
}

func PrintVersion() {
	const version = "Beta2"
	fmt.Println("easyss version", version)
}

func main() {
	var configFile string
	var printVer, debug, serverModel bool
	var cmdConfig Config

	flag.BoolVar(&printVer, "version", false, "print version")
	flag.StringVar(&configFile, "c", "config.json", "specify config file")
	flag.StringVar(&cmdConfig.Server, "s", "", "server address")
	flag.StringVar(&cmdConfig.Password, "k", "", "password")
	flag.IntVar(&cmdConfig.ServerPort, "p", 0, "server port")
	flag.IntVar(&cmdConfig.Timeout, "t", 300, "timeout in seconds")
	flag.IntVar(&cmdConfig.LocalPort, "l", 0, "local socks5 proxy port")
	flag.StringVar(&cmdConfig.Method, "m", "", "encryption method, default: aes-256-cfb")
	flag.BoolVar(&debug, "d", false, "print debug message")
	flag.BoolVar(&serverModel, "server", false, "server model")

	flag.Parse()

	if printVer {
		PrintVersion()
		os.Exit(0)
	}

	if debug {
		log.SetLevel(log.DebugLevel)
	}

	exists, err := utils.FileExists(configFile)
	if !exists || err != nil {
		log.Debugf("config file err:%v", err)

		binDir := path.Dir(os.Args[0])
		configFile = path.Join(binDir, "config.json")

		log.Debugf("config file not found, try config file %s", configFile)
	}

	config, err := ParseConfig(configFile)
	if err != nil {
		config = &cmdConfig
		if !os.IsNotExist(errors.Cause(err)) {
			log.Errorf("error reading %s: %+v", configFile, err)
			os.Exit(1)
		}
	} else {
		UpdateConfig(config, &cmdConfig)
	}

	if config.Method == "" {
		config.Method = "aes-256-gcm"
	}

	if serverModel {
		if config.ServerPort == 0 || config.Password == "" {
			log.Fatalln("server port and password should not empty")
		}

		tcpRemote(config)
	} else {
		if config.Password == "" || config.Server == "" || config.ServerPort == 0 {
			log.Fatalln("server address, server port and password should not empty")
		}

		pacChan := make(chan PACStatus, 1)

		t := NewTray(pacChan)
		p := NewPAC(config.LocalPort, pacChan)
		go p.Serve() // system pac configuration
		go tcpLocal(config)

		t.Run() // system tray management
	}

}
