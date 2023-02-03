package easyss

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coocood/freecache"
	"github.com/miekg/dns"
	"github.com/nange/easypool"
	"github.com/nange/easyss/v2/cipherstream"
	"github.com/nange/easyss/v2/util"
	"github.com/oschwald/geoip2-golang"
	utls "github.com/refraction-networking/utls"
	log "github.com/sirupsen/logrus"
	"github.com/txthinking/socks5"
)

const (
	// DefaultDNSCacheSize set default dns cache size to 2MB
	DefaultDNSCacheSize = 2 * 1024 * 1024
	// DefaultDNSCacheSec the default expire time for dns cache
	DefaultDNSCacheSec = 2 * 60 * 60
)

const (
	UDPLocksCount    = 256
	UDPLocksAndOpVal = 255
)

var (
	//go:embed geodata/geoip_cn_private.mmdb
	geoIPCNPrivate []byte
	//go:embed geodata/geosite_cn.txt
	geoSiteCN []byte
)

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
				log.Errorf("[EASYSS] compile geosite string:%s, err:%s", string(line), err.Error())
				continue
			}
			gs.regexpDomain = append(gs.regexpDomain, re)
			continue
		}

		gs.domain[string(line)] = struct{}{}
	}

	return gs
}

func domainRoot(domain string) string {
	var firstDot, lastDot int
	for {
		firstDot = strings.Index(domain, ".")
		lastDot = strings.LastIndex(domain, ".")
		if firstDot == lastDot {
			return domain
		}
		domain = domain[firstDot+1:]
	}
}

func (gs *GeoSite) SiteAtCN(domain string) bool {
	if _, ok := gs.fullDomain[domain]; ok {
		return true
	}
	if _, ok := gs.domain[domain]; ok {
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

type ProxyRule int

const (
	ProxyRuleUnknown ProxyRule = iota
	ProxyRuleAuto
	ProxyRuleProxy
	ProxyRuleDirect
)

func ParseProxyRuleFromString(rule string) ProxyRule {
	m := map[string]ProxyRule{
		"auto":   ProxyRuleAuto,
		"proxy":  ProxyRuleProxy,
		"direct": ProxyRuleDirect,
	}
	if r, ok := m[rule]; ok {
		return r
	}

	return ProxyRuleUnknown
}

type Easyss struct {
	config          *Config
	serverIP        string
	stat            *Statistics
	localGw         string
	localDev        string
	devIndex        int
	directDNSServer string
	dnsCache        *freecache.Cache
	directDNSCache  *freecache.Cache
	geoipDB         *geoip2.Reader
	geosite         *GeoSite
	// the user custom ip/domain list which have the highest priority
	customDirectIPs     map[string]struct{}
	customDirectDomains map[string]struct{}
	// only used on darwin(MacOS)
	originDNS []string

	// locks for udp request
	udpLocks [UDPLocksCount]sync.Mutex

	// the mu Mutex to protect below fields
	mu               *sync.RWMutex
	tcpPool          easypool.Pool
	socksServer      *socks5.Server
	httpProxyServer  *http.Server
	dnsForwardServer *dns.Server
	closing          chan struct{}
	enabledTun2socks bool
	proxyRule        ProxyRule
}

func New(config *Config) (*Easyss, error) {
	ss := &Easyss{
		config:         config,
		stat:           &Statistics{},
		dnsCache:       freecache.NewCache(DefaultDNSCacheSize),
		directDNSCache: freecache.NewCache(DefaultDNSCacheSize),
		closing:        make(chan struct{}, 1),
		mu:             &sync.RWMutex{},
	}
	proxyRule := ParseProxyRuleFromString(config.ProxyRule)
	if proxyRule == ProxyRuleUnknown {
		panic("unknown proxy rule:" + config.ProxyRule)
	}
	ss.proxyRule = proxyRule

	db, err := geoip2.FromBytes(geoIPCNPrivate)
	if err != nil {
		panic(err)
	}
	ss.geoipDB = db
	ss.geosite = NewGeoSite(geoSiteCN)

	if err := ss.loadCustomIPDomains(); err != nil {
		log.Errorf("[EASYSS] load custom ip/domains err:%s", err.Error())
	}

	if err := ss.initDirectDNSServer(); err != nil {
		log.Errorf("[EASYSS] init direct dns server:%v", err)
		return nil, err
	}

	if err := ss.initServerIPAndDNSCache(); err != nil {
		log.Errorf("[EASYSS] init server ip and dns cache:%v", err)
		return nil, err
	}

	if err := ss.initLocalGatewayAndDevice(); err != nil {
		log.Errorf("[EASYSS] init local gateway and device:%v", err)
		return nil, err
	}

	// get origin dns on darwin
	ds, err := util.SysDNS()
	if err != nil {
		log.Errorf("[EASYSS] get system dns err:%v", err)
	}
	ss.originDNS = ds

	go ss.printStatistics()

	return ss, err
}

func (ss *Easyss) loadCustomIPDomains() error {
	ss.customDirectIPs = make(map[string]struct{})
	ss.customDirectDomains = make(map[string]struct{})

	directIPs, err := util.ReadFileLinesMap(ss.config.DirectIPsFile)
	if err != nil {
		return err
	}
	if len(directIPs) > 0 {
		log.Infof("[EASYSS] load custom direct ips success, len:%d", len(directIPs))
		ss.customDirectIPs = directIPs
	}

	directDomains, err := util.ReadFileLinesMap(ss.config.DirectDomainsFile)
	if err != nil {
		return err
	}
	if len(directDomains) > 0 {
		log.Infof("[EASYSS] load custom direct domains success, len:%d", len(directDomains))
		ss.customDirectDomains = directDomains
	}

	return nil
}

func (ss *Easyss) initDirectDNSServer() error {
	for i, server := range DefaultDirectDNSServers {
		msg, _, err := ss.DNSMsg(server, DefaultDNSServerDomains[i])
		if err != nil {
			log.Warnf("[EASYSS] direct dns server %s is unavailable:%s, retry next after 1s",
				server, err.Error())
			time.Sleep(time.Second)
			continue
		}
		if msg != nil {
			ss.directDNSServer = server
			log.Infof("[EASYSS] set direct dns server to %s", server)
			return nil
		}
	}

	return errors.New("all direct dns server is unavailable, or the network is unavailable on this server")
}

func (ss *Easyss) initServerIPAndDNSCache() error {
	if !util.IsIP(ss.Server()) {
		msg, msgAAAA, err := ss.DNSMsg(ss.directDNSServer, ss.Server())
		if err != nil {
			log.Errorf("[EASYSS] query dns failed for %s from %s err:%s",
				ss.Server(), ss.directDNSServer, err.Error())
			return err
		}
		if msg != nil {
			log.Infof("[EASYSS] query dns success for %s from %s", ss.Server(), ss.directDNSServer)
		}

		if msg != nil && msgAAAA != nil {
			if len(msg.Answer) > 0 {
				ss.serverIP = msg.Answer[0].(*dns.A).A.String()
				_ = ss.SetDNSCache(msg, true, true)
				_ = ss.SetDNSCache(msg, true, false)
				_ = ss.SetDNSCache(msgAAAA, true, true)
				_ = ss.SetDNSCache(msgAAAA, true, false)
			} else {
				return errors.New("dns result is empty for " + ss.Server())
			}
		}
	} else {
		ss.serverIP = ss.Server()
	}

	return nil
}

func (ss *Easyss) initLocalGatewayAndDevice() error {
	switch runtime.GOOS {
	case "linux", "windows", "darwin":
		gw, dev, err := util.SysGatewayAndDevice()
		if err != nil {
			log.Errorf("[EASYSS] get system gateway and device err:%s", err.Error())
		}
		ss.localGw = gw
		ss.localDev = dev

		iface, err := net.InterfaceByName(dev)
		if err != nil {
			log.Errorf("[EASYSS] interface by name err:%v", err)
			return err
		}
		ss.devIndex = iface.Index
	}

	return nil
}

func (ss *Easyss) InitTcpPool() error {
	if ss.DisableUTLS() {
		log.Infof("[EASYSS] uTLS is disabled")
	} else {
		log.Infof("[EASYSS] uTLS is enabled")
	}

	var certPool *x509.CertPool
	if ss.CAPath() != "" {
		log.Infof("[EASYSS] using self-signed cert, ca-path:%s", ss.CAPath())
		certPool = x509.NewCertPool()
		caBuf, err := os.ReadFile(ss.CAPath())
		if err != nil {
			return err
		}
		if ok := certPool.AppendCertsFromPEM(caBuf); !ok {
			return errors.New("append certs from pem failed")
		}
	}

	factory := func() (net.Conn, error) {
		ctx, cancel := context.WithTimeout(context.Background(), ss.Timeout())
		defer cancel()

		if ss.DisableUTLS() {
			dialer := &tls.Dialer{
				Config: &tls.Config{RootCAs: certPool},
			}
			return dialer.DialContext(ctx, "tcp", ss.ServerAddr())
		}

		conn, err := net.DialTimeout("tcp", ss.ServerAddr(), ss.Timeout())
		if err != nil {
			return nil, err
		}

		uConn := utls.UClient(
			conn,
			&utls.Config{
				ServerName: ss.Server(),
				RootCAs:    certPool,
			},
			utls.HelloChrome_Auto)
		if err := uConn.HandshakeContext(ctx); err != nil {
			return nil, err
		}

		return uConn, nil
	}

	config := &easypool.PoolConfig{
		InitialCap:  5,
		MaxCap:      40,
		MaxIdle:     5,
		Idletime:    time.Minute,
		MaxLifetime: 15 * time.Minute,
		Factory:     factory,
	}
	tcpPool, err := easypool.NewHeapPool(config)
	ss.SetPool(tcpPool)

	return err
}

func (ss *Easyss) ConfigClone() *Config {
	return ss.config.Clone()
}

func (ss *Easyss) LocalPort() int {
	return ss.config.LocalPort
}

func (ss *Easyss) LocalHTTPPort() int {
	return ss.config.HTTPPort
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

func (ss *Easyss) DirectDNSServer() string {
	return ss.directDNSServer
}

func (ss *Easyss) ServerList() []ServerConfig {
	return ss.config.ServerList
}

func (ss *Easyss) ServerListAddrs() []string {
	var list []string
	for _, s := range ss.config.ServerList {
		list = append(list, fmt.Sprintf("%s:%d", s.Server, s.ServerPort))
	}
	return list
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

func (ss *Easyss) LocalHttpAddr() string {
	return fmt.Sprintf("%s:%d", "127.0.0.1", ss.LocalHTTPPort())
}

func (ss *Easyss) BindAll() bool {
	return ss.config.BindALL
}

func (ss *Easyss) DisableUTLS() bool {
	return ss.config.DisableUTLS
}

func (ss *Easyss) EnableForwardDNS() bool {
	return ss.config.EnableForwardDNS
}

func (ss *Easyss) CAPath() string {
	return ss.config.CAPath
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

func (ss *Easyss) AvailConnFromPool() (conn net.Conn, err error) {
	pool := ss.Pool()
	if pool == nil {
		return nil, errors.New("pool is closed")
	}

	poolLen := pool.Len()
	for i := 0; i < poolLen+2; i++ {
		conn, err = pool.Get()
		if err != nil {
			log.Warnf("[EASYSS] get conn from pool failed:%v", err)
			continue
		}

		err = func() (er error) {
			var csStream net.Conn
			csStream, er = cipherstream.New(conn, ss.Password(), cipherstream.MethodAes256GCM, util.FrameTypePing)
			if er != nil {
				return er
			}

			cs := csStream.(*cipherstream.CipherStream)
			defer func() {
				if er != nil {
					MarkCipherStreamUnusable(cs)
					conn.Close()
				}
				cs.Release()
			}()

			ping := []byte(strconv.FormatInt(time.Now().UnixNano(), 10))
			if er = cs.WritePing(ping, util.FlagNeedACK); er != nil {
				return
			}
			if er = SetCipherDeadline(cs, time.Now().Add(time.Second)); er != nil {
				return
			}
			var payload []byte
			if payload, er = cs.ReadPing(); er != nil {
				return
			} else if !bytes.Equal(ping, payload) {
				er = errors.New("the payload of ping not equals send value")
				return
			}
			if er = SetCipherDeadline(cs, time.Time{}); er != nil {
				return
			}
			return
		}()
		if err != nil {
			log.Warnf("[EASYSS] write ping to cipher stream:%v", err)
			continue
		}

		break
	}

	return
}

func (ss *Easyss) SetSocksServer(server *socks5.Server) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	ss.socksServer = server
}

func (ss *Easyss) SetForwardDNSServer(server *dns.Server) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	ss.dnsForwardServer = server
}

func (ss *Easyss) EnabledTun2socks() bool {
	ss.mu.RLock()
	defer ss.mu.RUnlock()
	return ss.enabledTun2socks
}

func (ss *Easyss) SetTun2socks(enable bool) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	ss.enabledTun2socks = enable
}

func (ss *Easyss) EnabledTun2socksFromConfig() bool {
	return ss.config.EnableTun2socks
}

func (ss *Easyss) ProxyRule() ProxyRule {
	ss.mu.RLock()
	defer ss.mu.RUnlock()
	return ss.proxyRule
}

func (ss *Easyss) SetProxyRule(rule ProxyRule) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	ss.proxyRule = rule
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

func (ss *Easyss) RenewDNSCache(name, qtype string, isDirect bool) bool {
	if isDirect {
		if err := ss.directDNSCache.Touch([]byte(name+qtype), DefaultDNSCacheSec); err != nil {
			return false
		}
	}
	if err := ss.dnsCache.Touch([]byte(name+qtype), DefaultDNSCacheSec); err != nil {
		return false
	}
	return true
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
		expireSec := DefaultDNSCacheSec
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

func (ss *Easyss) DNSMsg(dnsServer, domain string) (*dns.Msg, *dns.Msg, error) {
	c := new(dns.Client)

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	m.RecursionDesired = true

	r, _, err := c.Exchange(m, dnsServer)
	if err != nil {
		return nil, nil, err
	}
	if r.Rcode != dns.RcodeSuccess {
		return nil, nil, fmt.Errorf("dns query response Rcode:%v not equals RcodeSuccess", r.Rcode)
	}

	m.SetQuestion(dns.Fqdn(domain), dns.TypeAAAA)
	rAAAA, _, err := c.Exchange(m, dnsServer)
	if err != nil {
		return nil, nil, err
	}
	if rAAAA.Rcode != dns.RcodeSuccess {
		return nil, nil, fmt.Errorf("dns query response Rcode:%v not equals RcodeSuccess", r.Rcode)
	}

	return r, rAAAA, nil
}

func (ss *Easyss) HostShouldDirect(host string) bool {
	if ss.ProxyRule() == ProxyRuleDirect {
		return true
	}
	if ss.ProxyRule() == ProxyRuleProxy {
		return false
	}

	if util.IsIP(host) {
		if _, ok := ss.customDirectIPs[host]; ok {
			return true
		}
	} else {
		if _, ok := ss.customDirectDomains[host]; ok {
			return true
		}
		domain := domainRoot(host)
		if _, ok := ss.customDirectDomains[domain]; ok {
			return true
		}
		// if the host end with .cn, return true
		if strings.HasSuffix(host, ".cn") {
			return true
		}
	}

	return ss.HostAtCNOrPrivate(host)
}

func (ss *Easyss) HostAtCNOrPrivate(host string) bool {
	if host == "" {
		return false
	}

	if util.IsIP(host) {
		return ss.IPAtCNOrPrivate(host)
	}

	return ss.geosite.SiteAtCN(host)
}

func (ss *Easyss) IPAtCNOrPrivate(ip string) bool {
	_ip := net.ParseIP(ip)
	if _ip == nil {
		return false
	}
	country, err := ss.geoipDB.Country(_ip)
	if err != nil {
		return false
	}

	if country.Country.IsoCode == "CN" || country.Country.IsoCode == "PRIVATE" {
		return true
	}

	return false
}

func (ss *Easyss) Close() error {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	var err error
	if ss.enabledTun2socks {
		err = ss.closeTun2socks()
	}
	if ss.tcpPool != nil {
		ss.tcpPool.Close()
		ss.tcpPool = nil
	}
	if ss.httpProxyServer != nil {
		err = ss.httpProxyServer.Close()
		ss.httpProxyServer = nil
	}
	if ss.socksServer != nil {
		err = ss.socksServer.Shutdown()
		ss.socksServer = nil
	}
	if ss.dnsForwardServer != nil {
		err = ss.dnsForwardServer.Shutdown()
		ss.dnsForwardServer = nil
	}
	if ss.closing != nil {
		close(ss.closing)
		ss.closing = nil
	}
	return err
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
			log.Debugf("[EASYSS] send size: %vMB, recive size: %vMB", sendSize, receiveSize)
		case <-closing:
			return
		}
	}
}
