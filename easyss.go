package easyss

import (
	"fmt"
	"io"
	"net"
	"time"

	rotatelogs "github.com/lestrrat-go/file-rotatelogs"
	"github.com/nange/easypool"
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
	config  *Config
	tcpPool easypool.Pool

	LogFileWriter io.Writer
}

func New(config *Config) (*Easyss, error) {
	ss := &Easyss{config: config}

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

func (ss *Easyss) LocalPort() int {
	return ss.config.LocalPort
}

func (ss *Easyss) ServerPort() int {
	return ss.config.ServerPort
}

func (ss *Easyss) LocalAddr() string {
	return fmt.Sprintf("%s:%d", "127.0.0.1", ss.LocalPort())
}

func (ss *Easyss) Close() {
	if ss.tcpPool != nil {
		ss.tcpPool.Close()
	}
}
