package easyss

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	_ "embed"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coocood/freecache"
	"github.com/miekg/dns"
	"github.com/nange/easypool"
	"github.com/nange/easyss/util"
	"github.com/oschwald/geoip2-golang"
	utls "github.com/refraction-networking/utls"
	log "github.com/sirupsen/logrus"
	"github.com/txthinking/socks5"
)

const version = "v1.5.0"

var (
	//go:embed geodata/geoip_cn_private.mmdb
	geoIPCNPrivate []byte
	//go:embed geodata/geosite_cn.txt
	geoSiteCN []byte
)

func PrintVersion() {
	fmt.Println("easyss version", version)
}

type Statistics struct {
	BytesSend    atomic.Int64
	BytesReceive atomic.Int64
}

type GeoSite struct {
	domain       map[string]struct{}
	fullDomain   map[string]struct{}
	regexpDomain []*regexp.Regexp
}

func NewGeoSite(data []byte) *GeoSite {
	gs := &GeoSite{
		domain:     make(map[string]struct{}),
		fullDomain: make(map[string]struct{}),
	}

	r := bufio.NewReader(bytes.NewReader(data))
	for {
		line, _, err := r.ReadLine()
		if err == io.EOF {
			break
		}

		if bytes.HasPrefix(line, []byte("full:")) {
			gs.fullDomain[string(line[5:])] = struct{}{}
			continue
		}

		if bytes.HasPrefix(line, []byte("regexp:")) {
			line = line[7:]
			re, err := regexp.Compile(string(line))
			if err != nil {
				log.Errorf("compile geosite string:%s, err:%s", string(line), err.Error())
				continue
			}
			gs.regexpDomain = append(gs.regexpDomain, re)
			continue
		}

		gs.domain[string(line)] = struct{}{}
	}

	return gs
}

func (gs *GeoSite) SiteAtCN(domain string) bool {
	domainRoot := func(_domain string) string {
		var firstDot, lastDot int
		for {
			firstDot = strings.Index(_domain, ".")
			lastDot = strings.LastIndex(_domain, ".")
			if firstDot == lastDot {
				return _domain
			}
			_domain = _domain[firstDot+1:]
		}
	}

	if _, ok := gs.fullDomain[domain]; ok {
		return true
	}

	_domain := domainRoot(domain)
	if _, ok := gs.domain[_domain]; ok {
		return true
	}

	for _, re := range gs.regexpDomain {
		if re.MatchString(domain) {
			return true
		}
	}

	return false
}

type Easyss struct {
	config         *Config
	serverIP       string
	stat           *Statistics
	localGw        string
	localDev       string
	devIndex       int
	dnsCache       *freecache.Cache
	directDNSCache *freecache.Cache
	geoipDB        *geoip2.Reader
	geosite        *GeoSite

	// the mu Mutex to protect below fields
	mu              *sync.RWMutex
	tcpPool         easypool.Pool
	socksServer     *socks5.Server
	httpProxyServer *http.Server
	closing         chan struct{}
	tun2socksStatus Tun2socksStatus
}

func New(config *Config) (*Easyss, error) {
	ss := &Easyss{
		config:         config,
		stat:           &Statistics{},
		dnsCache:       freecache.NewCache(1024 * 1024),
		directDNSCache: freecache.NewCache(1024 * 1024),
		closing:        make(chan struct{}, 1),
		mu:             &sync.RWMutex{},
	}

	db, err := geoip2.FromBytes(geoIPCNPrivate)
	if err != nil {
		panic(err)
	}
	ss.geoipDB = db
	ss.geosite = NewGeoSite(geoSiteCN)

	msg, err := ss.ServerDNSMsg()
	if err != nil {
		log.Errorf("query server dns msg err:%s", err.Error())
	}
	if msg != nil {
		ss.serverIP = msg.Answer[0].(*dns.A).A.String()
		ss.SetDNSCache(msg, true, true)
		ss.SetDNSCache(msg, true, false)
	}

	switch runtime.GOOS {
	case "linux", "windows", "darwin":
		gw, dev, err := util.SysGatewayAndDevice()
		if err != nil {
			log.Errorf("get system gateway and device err:%s", err.Error())
		}
		ss.localGw = gw
		ss.localDev = dev

		iface, err := net.InterfaceByName(dev)
		if err != nil {
			log.Errorf("interface by name err:%v", err)
			return nil, err
		}
		ss.devIndex = iface.Index
	}

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

func (ss *Easyss) LocalDeviceIndex() int {
	return ss.devIndex
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

func (ss *Easyss) Tun2socksStatus() Tun2socksStatus {
	ss.mu.RLock()
	defer ss.mu.RUnlock()
	return ss.tun2socksStatus
}

func (ss *Easyss) SetTun2socksStatus(status Tun2socksStatus) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	ss.tun2socksStatus = status
}

func (ss *Easyss) Tun2socksStatusAuto() bool {
	ss.mu.RLock()
	defer ss.mu.RUnlock()
	return ss.tun2socksStatus == Tun2socksStatusAuto
}

func (ss *Easyss) Tun2socksStatusOn() bool {
	ss.mu.RLock()
	defer ss.mu.RUnlock()
	return ss.tun2socksStatus == Tun2socksStatusOn
}

func (ss *Easyss) Tun2socksStatusOff() bool {
	ss.mu.RLock()
	defer ss.mu.RUnlock()
	return ss.tun2socksStatus == Tun2socksStatusOff
}

func (ss *Easyss) Tun2socksModelFromConfig() string {
	return ss.config.Tun2socksModel
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

func (ss *Easyss) DNSCache(name, qtype string, isDirect bool) *dns.Msg {
	var v []byte
	var err error
	if isDirect {
		v, err = ss.directDNSCache.Get([]byte(name + qtype))
	} else {
		v, err = ss.dnsCache.Get([]byte(name + qtype))
	}
	if err != nil || len(v) == 0 {
		return nil
	}

	msg := &dns.Msg{}
	if err := msg.Unpack(v); err != nil {
		return nil
	}

	return msg
}

func (ss *Easyss) RenewDNSCache(name, qtype string, isDirect bool) {
	if isDirect {
		ss.directDNSCache.Touch([]byte(name+qtype), 8*60*60)
		return
	}
	ss.dnsCache.Touch([]byte(name+qtype), 8*60*60)
}

func (ss *Easyss) SetDNSCache(msg *dns.Msg, noExpire, isDirect bool) error {
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
		key := []byte(q.Name + dns.TypeToString[q.Qtype])
		if isDirect {
			return ss.directDNSCache.Set(key, v, expireSec)
		}
		return ss.dnsCache.Set(key, v, expireSec)
	}

	return nil
}

func (ss *Easyss) ServerDNSMsg() (*dns.Msg, error) {
	c := new(dns.Client)

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(ss.Server()), dns.TypeA)
	m.RecursionDesired = true

	r, _, err := c.Exchange(m, "114.114.114.114:53")
	if err != nil {
		return nil, err
	}

	if r.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("dns query response Rcode:%v not equals RcodeSuccess", r.Rcode)
	}

	return r, nil
}

func (ss *Easyss) HostAtCN(host string) bool {
	if host == "" {
		return false
	}

	if util.IsIP(host) {
		return ss.IPAtCN(host)
	}

	return ss.geosite.SiteAtCN(host)
}

func (ss *Easyss) IPAtCN(ip string) bool {
	_ip := net.ParseIP(ip)
	if _ip == nil {
		return false
	}
	country, err := ss.geoipDB.Country(_ip)
	if err != nil {
		return false
	}

	if country.Country.IsoCode == "CN" {
		return true
	}

	return false
}

func (ss *Easyss) Close() {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	if ss.tun2socksStatus != Tun2socksStatusOff {
		ss.closeTun2socks()
	}
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
			receiveSize := ss.stat.BytesReceive.Load() / (1024 * 1024)
			log.Debugf("easyss send data size: %vMB, recive data size: %vMB", sendSize, receiveSize)
		case <-closing:
			return
		}
	}
}
