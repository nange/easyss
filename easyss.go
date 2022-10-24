package easyss

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nange/easypool"
	"github.com/nange/easyss/util"
	log "github.com/sirupsen/logrus"
	"github.com/txthinking/socks5"
)

const version = "1.3.0"

func PrintVersion() {
	fmt.Println("easyss version", version)
}

type Statistics struct {
	BytesSend   atomic.Int64
	BytesRecive atomic.Int64
}

type Easyss struct {
	config    *Config
	serverIPs []string
	stat      *Statistics

	tcpPool         easypool.Pool
	socksServer     *socks5.Server
	httpProxyServer *http.Server
	closing         chan struct{}
	mu              *sync.RWMutex
}

func New(config *Config) (*Easyss, error) {
	ss := &Easyss{
		config:  config,
		stat:    &Statistics{},
		closing: make(chan struct{}, 1),
		mu:      &sync.RWMutex{},
	}

	var err error
	var ips []string
	if !util.IsIP(config.Server) {
		ips, err = net.LookupHost(config.Server)
		ss.serverIPs = ips
	}

	go ss.printStatistics()

	return ss, err
}

func (ss *Easyss) InitTcpPool() error {
	factory := func() (net.Conn, error) {
		return tls.Dial("tcp", fmt.Sprintf("%s:%d", ss.config.Server, ss.config.ServerPort), nil)
	}
	config := &easypool.PoolConfig{
		InitialCap:  10,
		MaxCap:      50,
		MaxIdle:     10,
		Idletime:    5 * time.Minute,
		MaxLifetime: 30 * time.Minute,
		Factory:     factory,
	}
	tcpPool, err := easypool.NewHeapPool(config)
	ss.SetPool(tcpPool)
	return err
}

func (ss *Easyss) LocalPort() int {
	return ss.config.LocalPort
}

func (ss *Easyss) LocalHttpProxyPort() int {
	return ss.config.LocalPort + 1000
}

func (ss *Easyss) LocalPacPort() int {
	return ss.config.LocalPort + 1001
}

func (ss *Easyss) ServerPort() int {
	return ss.config.ServerPort
}

func (ss *Easyss) Password() string {
	return ss.config.Password
}

func (ss *Easyss) Method() string {
	return ss.config.Method
}

func (ss *Easyss) Server() string {
	return ss.config.Server
}

func (ss *Easyss) Timeout() int {
	return ss.config.Timeout
}

func (ss *Easyss) LocalAddr() string {
	return fmt.Sprintf("%s:%d", "127.0.0.1", ss.LocalPort())
}

func (ss *Easyss) BindAll() bool {
	return ss.config.BindALL
}

func (ss *Easyss) ConfigFilename() string {
	if ss.config.ConfigFile == "" {
		return ""
	}
	return filepath.Base(ss.config.ConfigFile)
}

func (ss *Easyss) Pool() easypool.Pool {
	ss.mu.RLock()
	defer ss.mu.RUnlock()
	return ss.tcpPool
}

func (ss *Easyss) SetSocksServer(server *socks5.Server) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	ss.socksServer = server
}

func (ss *Easyss) SetHttpProxyServer(server *http.Server) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	ss.httpProxyServer = server
}

func (ss *Easyss) SetPool(pool easypool.Pool) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	ss.tcpPool = pool
}

func (ss *Easyss) Close() {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	if ss.tcpPool != nil {
		ss.tcpPool.Close()
		ss.tcpPool = nil
	}
	if ss.httpProxyServer != nil {
		ss.httpProxyServer.Close()
		ss.httpProxyServer = nil
	}
	if ss.socksServer != nil {
		ss.socksServer.Shutdown()
		ss.socksServer = nil
	}
	if ss.closing != nil {
		close(ss.closing)
		ss.closing = nil
	}
}

func (ss *Easyss) printStatistics() {
	ss.mu.Lock()
	closing := ss.closing
	ss.mu.Unlock()
	for {
		select {
		case <-time.After(time.Hour):
			sendSize := ss.stat.BytesSend.Load() / (1024 * 1024)
			receiveSize := ss.stat.BytesRecive.Load() / (1024 * 1024)
			log.Debugf("easyss send data size: %vMB, recive data size: %vMB", sendSize, receiveSize)
		case <-closing:
			return
		}
	}
}
