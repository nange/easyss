package easyss

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coocood/freecache"
	"github.com/miekg/dns"
	"github.com/nange/easypool"
	"github.com/nange/easyss/util"
	utls "github.com/refraction-networking/utls"
	log "github.com/sirupsen/logrus"
	"github.com/txthinking/socks5"
)

const version = "1.4.0"

func PrintVersion() {
	fmt.Println("easyss version", version)
}

type Statistics struct {
	BytesSend   atomic.Int64
	BytesRecive atomic.Int64
}

type Easyss struct {
	config   *Config
	serverIP string
	stat     *Statistics
	localGw  string
	localDev string
	dnsCache *freecache.Cache

	tcpPool          easypool.Pool
	socksServer      *socks5.Server
	httpProxyServer  *http.Server
	closing          chan struct{}
	tun2socksEnabled bool
	mu               *sync.RWMutex
}

func New(config *Config) (*Easyss, error) {
	ss := &Easyss{
		config:   config,
		stat:     &Statistics{},
		dnsCache: freecache.NewCache(2 * 1024 * 1024),
		closing:  make(chan struct{}, 1),
		mu:       &sync.RWMutex{},
	}

	msg, err := ss.ServerDNSMsg()
	if err != nil {
		log.Errorf("query server dns msg err:%s", err.Error())
	}
	if msg != nil {
		ss.serverIP = msg.Answer[0].(*dns.A).A.String()
		ss.SetDNSCache(msg, true)
	}

	gw, dev, err := util.SysGatewayAndDevice()
	if err != nil {
		log.Errorf("get system gateway and device err:%s", err.Error())
	}
	ss.localGw = gw
	ss.localDev = dev

	go ss.printStatistics()

	return ss, err
}

func (ss *Easyss) InitTcpPool() error {
	if ss.DisableUTLS() {
		log.Infof("uTLS is disabled")
	} else {
		log.Infof("uTLS is enabled")
	}

	factory := func() (net.Conn, error) {
		ctx, cancel := context.WithTimeout(context.Background(), ss.Timeout())
		defer cancel()

		if ss.DisableUTLS() {
			dialer := new(tls.Dialer)
			return dialer.DialContext(ctx, "tcp", ss.ServerAddr())
		}

		conn, err := net.DialTimeout("tcp", ss.ServerAddr(), ss.Timeout())
		if err != nil {
			return nil, err
		}

		uConn := utls.UClient(conn, &utls.Config{ServerName: ss.Server()}, utls.HelloChrome_Auto)
		if err := uConn.HandshakeContext(ctx); err != nil {
			return nil, err
		}

		return uConn, nil
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

func (ss *Easyss) ServerIP() string {
	return ss.serverIP
}

func (ss *Easyss) ServerAddr() string {
	return fmt.Sprintf("%s:%d", ss.Server(), ss.ServerPort())
}

func (ss *Easyss) Socks5ProxyAddr() string {
	return fmt.Sprintf("socks5://%s", ss.LocalAddr())
}

func (ss *Easyss) LocalGateway() string {
	return ss.localGw
}

func (ss *Easyss) LocalDevice() string {
	return ss.localDev
}

func (ss *Easyss) Timeout() time.Duration {
	return time.Duration(ss.config.Timeout) * time.Second
}

func (ss *Easyss) LocalAddr() string {
	return fmt.Sprintf("%s:%d", "127.0.0.1", ss.LocalPort())
}

func (ss *Easyss) BindAll() bool {
	return ss.config.BindALL
}

func (ss *Easyss) DisableUTLS() bool {
	return ss.config.DisableUTLS
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

func (ss *Easyss) DNSCache(name, qtype string) *dns.Msg {
	v, err := ss.dnsCache.Get([]byte(name + qtype))
	if err != nil || len(v) == 0 {
		return nil
	}

	msg := &dns.Msg{}
	if err := msg.Unpack(v); err != nil {
		return nil
	}

	return msg
}

func (ss *Easyss) RenewDNSCache(name, qtype string) {
	ss.dnsCache.Touch([]byte(name+qtype), 8*60*60)
}

func (ss *Easyss) SetDNSCache(msg *dns.Msg, noExpire bool) error {
	if msg == nil {
		return nil
	}
	if len(msg.Question) == 0 {
		return nil
	}

	q := msg.Question[0]
	if q.Qtype == dns.TypeA || q.Qtype == dns.TypeAAAA {
		v, err := msg.Pack()
		if err != nil {
			return err
		}
		expireSec := 8 * 60 * 60
		if noExpire {
			expireSec = 0
		}
		return ss.dnsCache.Set([]byte(q.Name+dns.TypeToString[q.Qtype]), v, expireSec)
	}

	return nil
}

func (ss *Easyss) ServerDNSMsg() (*dns.Msg, error) {
	c := new(dns.Client)

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(ss.Server()), dns.TypeA)
	m.RecursionDesired = true

	dnsAddr := util.SysDNSServerAddr()
	if dnsAddr == "" {
		return nil, errors.New("system dns server addr is empty")
	}
	r, _, err := c.Exchange(m, dnsAddr)
	if err != nil {
		return nil, err
	}

	if r.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("dns query response Rcode:%v not equals RcodeSuccess", r.Rcode)
	}

	return r, nil
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
	if ss.tun2socksEnabled {
		ss.closeTun2socks()
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
