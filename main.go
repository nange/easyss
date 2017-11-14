package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"path"
	"time"

	quic "github.com/lucas-clemente/quic-go"
	"github.com/nange/easypool"
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

type Easyss struct {
	config    *Config
	localSess quic.Session
	sessChan  chan sessOpts
	tcpPool   easypool.Pool
}

func New(config *Config) (*Easyss, error) {
	ss := &Easyss{
		config:   config,
		sessChan: make(chan sessOpts, 10),
	}

	factory := func() (net.Conn, error) {
		return net.Dial("tcp", fmt.Sprintf("%s:%d", config.Server, config.ServerPort))
	}
	pconfig := &easypool.PoolConfig{
		InitialCap:  5,
		MaxCap:      50,
		MaxIdle:     10,
		Idletime:    2 * time.Minute,
		MaxLifetime: 15 * time.Minute,
		Factory:     factory,
	}
	tcppool, err := easypool.NewHeapPool(pconfig)
	if err != nil {
		return nil, err
	}
	ss.tcpPool = tcppool

	go ss.sessManage()

	return ss, nil
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
	flag.StringVar(&cmdConfig.Method, "m", "", "encryption method, default: aes-256-gcm")
	flag.BoolVar(&cmdConfig.EnableQuic, "quic", false, "enable quic if set this value to be true")
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

	ss, err := New(config)
	if err != nil {
		log.Fatalf("init Easyss err:%+v", err)
	}
	if serverModel {
		if config.ServerPort == 0 || config.Password == "" {
			log.Fatalln("server port and password should not empty")
		}

		ss.Remote()
	} else {
		if config.Password == "" || config.Server == "" || config.ServerPort == 0 {
			log.Fatalln("server address, server port and password should not empty")
		}

		pacChan := make(chan PACStatus, 1)

		p := NewPAC(config.LocalPort, pacChan)
		go p.Serve() // system pac configuration

		go ss.Local() // start local server

		t := NewTray(pacChan)
		t.Run() // system tray management
	}

}
