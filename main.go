package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"path"
	"time"

	"github.com/getlantern/systray"
	quic "github.com/lucas-clemente/quic-go"
	"github.com/nange/easypool"
	"github.com/nange/easyss/util"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

func init() {
	log.SetFormatter(&log.JSONFormatter{TimestampFormat: "2006-01-02 15:04:05.000"})
	log.SetLevel(log.InfoLevel)
}

func PrintVersion() {
	const version = "1.0"
	fmt.Println("easyss version", version)
}

type Easyss struct {
	config *Config
	quic   struct {
		localSess quic.Session
		sessChan  chan sessOpts
	}
	pac struct {
		ch   chan PACStatus
		url  string
		gurl string
	}
	tcpPool easypool.Pool

	logFileName string
}

func New(config *Config) (*Easyss, error) {
	ss := &Easyss{config: config}
	if !config.ServerModel {
		ss.pac.ch = make(chan PACStatus)
		ss.pac.url = fmt.Sprintf("http://localhost:%d%s", ss.config.LocalPort+1, pacpath)
		ss.pac.gurl = fmt.Sprintf("http://localhost:%d%s?global=true", ss.config.LocalPort+1, pacpath)
	}
	if config.EnableQuic {
		ss.quic.sessChan = make(chan sessOpts, 10)
	}
	ss.logFileName = util.GetLogFileName()
	return ss, nil
}

func (ss *Easyss) InitTcpPool() error {
	factory := func() (net.Conn, error) {
		return net.Dial("tcp", fmt.Sprintf("%s:%d", ss.config.Server, ss.config.ServerPort))
	}
	pconfig := &easypool.PoolConfig{
		InitialCap:  5,
		MaxCap:      30,
		MaxIdle:     5,
		Idletime:    time.Minute,
		MaxLifetime: 5 * time.Minute,
		Factory:     factory,
	}
	tcppool, err := easypool.NewHeapPool(pconfig)
	ss.tcpPool = tcppool
	return err
}

func main() {
	var configFile string
	var printVer, debug, godaemon bool
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
	flag.BoolVar(&cmdConfig.ServerModel, "server", false, "server model")
	flag.BoolVar(&godaemon, "daemon", true, "run app as a non-daemon with -daemon=false")

	flag.Parse()

	if printVer {
		PrintVersion()
		os.Exit(0)
	}
	// we starting easyss as daemon only in client model, and save logs to file
	if !cmdConfig.ServerModel {
		daemon(godaemon)
		fileout, err := util.GetLogFileWriter(LOG_MAX_AGE, LOG_ROTATION_TIME)
		if err != nil {
			log.Errorf("get log file output writer err:%v", err)
		} else {
			log.SetOutput(fileout)
		}
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

	ss, err := New(config)
	if err != nil {
		log.Fatalf("init Easyss err:%+v", err)
	}
	if config.ServerModel {
		if config.ServerPort == 0 || config.Password == "" {
			log.Fatalln("server port and password should not empty")
		}

		ss.Remote()
	} else {
		if config.Password == "" || config.Server == "" || config.ServerPort == 0 {
			log.Fatalln("server address, server port and password should not empty")
		}

		systray.Run(ss.trayReady, ss.trayExit) // system tray management
	}

}
