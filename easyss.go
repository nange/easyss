package easyss

import (
	"fmt"
	"io"
	"net"
	"time"

	rotatelogs "github.com/lestrrat/go-file-rotatelogs"
	"github.com/nange/easypool"
	log "github.com/sirupsen/logrus"
)

const PacPath = "/proxy.pac"

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
	pac    struct {
		ch   chan PACStatus
		url  string
		gurl string
	}
	tcpPool easypool.Pool

	LogFileWriter io.Writer
}

func New(config *Config) (*Easyss, error) {
	ss := &Easyss{config: config}
	if !config.ServerModel {
		ss.pac.ch = make(chan PACStatus)
		ss.pac.url = fmt.Sprintf("http://localhost:%d%s", ss.config.LocalPort+1, PacPath)
		ss.pac.gurl = fmt.Sprintf("http://localhost:%d%s?global=true", ss.config.LocalPort+1, PacPath)
	}

	return ss, nil
}

func (ss *Easyss) GetLogFileFullPathName() string {
	if rl, ok := ss.LogFileWriter.(*rotatelogs.RotateLogs); ok {
		return rl.CurrentFileName()
	}
	log.Errorf("get log file name failed!")
	return ""
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
