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
	"github.com/imroc/req/v3"
	"github.com/klauspost/compress/gzhttp"
	"github.com/miekg/dns"
	"github.com/nange/easypool"
	"github.com/nange/easyss/v2/cipherstream"
	"github.com/nange/easyss/v2/httptunnel"
	"github.com/nange/easyss/v2/log"
	"github.com/nange/easyss/v2/util"
	"github.com/oschwald/geoip2-golang"
	utls "github.com/refraction-networking/utls"
	"github.com/txthinking/socks5"
)

const (
	// DefaultDNSCacheSize set default dns cache size to 2MB
	DefaultDNSCacheSize = 2 * 1024 * 1024
	// DefaultDNSCacheSec the default expire time for dns cache
	DefaultDNSCacheSec = 2 * 60 * 60
)

const (
	UDPLocksCount    = 512
	UDPLocksAndOpVal = 511
)

const (
	MaxCap      int = 40
	MaxIdle     int = 5
	IdleTime        = time.Minute
	MaxLifetime     = 15 * time.Minute
)

const UserAgent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"

var (
	//go:embed assets/geodata/Country-only-cn-private.mmdb
	geoIPCNPrivate []byte
	//go:embed assets/geodata/direct-list.txt
	geoSiteDirect []byte
	//go:embed assets/geodata/block-list.txt
	geoSiteBlock []byte
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
				log.Error("[EASYSS] compile", "geosite", string(line), "err", err.Error())
				continue
			}
			gs.regexpDomain = append(gs.regexpDomain, re)
			continue
		}

		gs.domain[string(line)] = struct{}{}
	}

	return gs
}

func subDomains(domain string) []string {
	if domain == "" {
		return nil
	}
	subs := make([]string, 0, 8)

	i := strings.Index(domain, ".")
	for i > 0 {
		domain = domain[i+1:]
		subs = append(subs, domain)
		i = strings.Index(domain, ".")
	}
	if len(subs) > 1 {
		return subs[:len(subs)-1]
	}

	return nil
}

func (gs *GeoSite) FullMatch(domain string) bool {
	if gs.SimpleMatch(domain, true) {
		return true
	}

	for _, re := range gs.regexpDomain {
		if re.MatchString(domain) {
			return true
		}
	}

	return false
}

func (gs *GeoSite) SimpleMatch(domain string, matchSub bool) bool {
	if _, ok := gs.fullDomain[domain]; ok {
		return true
	}
	if _, ok := gs.domain[domain]; ok {
		return true
	}

	if matchSub {
		subs := subDomains(domain)
		for _, sub := range subs {
			if _, ok := gs.domain[sub]; ok {
				return true
			}
		}
	}

	return false
}

type HostRule int

const (
	HostRuleProxy HostRule = iota
	HostRuleDirect
	HostRuleBlock
)

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
	geoIPDB         *geoip2.Reader
	geoSiteDirect   *GeoSite
	geoSiteBlock    *GeoSite
	// the user custom ip/domain list which have the highest priority
	customDirectIPs     map[string]struct{}
	customDirectCIDRIPs []*net.IPNet
	customDirectDomains map[string]struct{}
	// only used on darwin(MacOS)
	originDNS []string

	// locks for udp request
	udpLocks [UDPLocksCount]sync.Mutex

	// only used for testing
	disableValidateAddr bool

	// only used for http outbound proto
	httpOutboundClient *req.Client

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

	if err := ss.cmdBeforeStartup(); err != nil {
		log.Error("[EASYSS] executing command before startup", "err", err)
		return nil, err
	}

	db, err := geoip2.FromBytes(geoIPCNPrivate)
	if err != nil {
		panic(err)
	}
	ss.geoIPDB = db
	ss.geoSiteDirect = NewGeoSite(geoSiteDirect)
	ss.geoSiteBlock = NewGeoSite(geoSiteBlock)

	if err := ss.initDirectDNSServer(); err != nil {
		log.Error("[EASYSS] init direct dns server", "err", err)
		return nil, err
	}

	if err := ss.loadCustomIPDomains(); err != nil {
		log.Error("[EASYSS] load custom ip/domains", "err", err)
	}

	if err := ss.initServerIPAndDNSCache(); err != nil {
		log.Error("[EASYSS] init server ip and dns cache", "err", err)
		return nil, err
	}

	if err := ss.initLocalGatewayAndDevice(); err != nil {
		log.Error("[EASYSS] init local gateway and device", "err", err)
		return nil, err
	}

	if err := ss.initHTTPOutboundClient(); err != nil {
		log.Error("[EASYSS] init http outbound client", "err", err)
		return nil, err
	}

	// get origin dns on darwin
	ds, err := util.SysDNS()
	if err != nil {
		log.Error("[EASYSS] get system dns", "err", err)
	}
	ss.originDNS = ds

	go ss.background()

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
		log.Info("[EASYSS] load custom direct ips success", "len", len(directIPs))
		for k := range directIPs {
			_, ipnet, err := net.ParseCIDR(k)
			if err != nil {
				continue
			}
			if ipnet != nil {
				ss.customDirectCIDRIPs = append(ss.customDirectCIDRIPs, ipnet)
				delete(directIPs, k)
			}
		}
		ss.customDirectIPs = directIPs
	}

	directDomains, err := util.ReadFileLinesMap(ss.config.DirectDomainsFile)
	if err != nil {
		return err
	}

	if len(directDomains) > 0 {
		log.Info("[EASYSS] load custom direct domains success", "len", len(directDomains))
		ss.customDirectDomains = directDomains
		// not only direct the domains but also the ips of domains
		for domain := range directDomains {
			ips, err := util.LookupIPV4From(ss.directDNSServer, domain)
			if err != nil {
				log.Error("[EASYSS] query dns for custom direct domain", "domain", domain, "err", err)
				continue
			}
			for _, ip := range ips {
				ss.customDirectIPs[ip.String()] = struct{}{}
			}
		}
	}

	return nil
}

func (ss *Easyss) initDirectDNSServer() error {
	for i, server := range DefaultDirectDNSServers {
		msg, _, err := ss.DNSMsg(server, DefaultDNSServerDomains[i])
		if err != nil {
			log.Warn("[EASYSS] direct dns server is unavailable, retry next after 1s",
				"server", server, "err", err)
			time.Sleep(time.Second)
			continue
		}
		if msg != nil {
			ss.directDNSServer = server
			log.Info("[EASYSS] set direct dns server to", "server", server)
			return nil
		}
	}

	return errors.New("all direct dns server is unavailable, or the network is unavailable on this server")
}

func (ss *Easyss) initServerIPAndDNSCache() error {
	if !util.IsIP(ss.Server()) {
		var msg, msgAAAA *dns.Msg
		var err error
		for i := 1; i <= 3; i++ {
			msg, msgAAAA, err = ss.DNSMsg(ss.directDNSServer, ss.Server())
			if err != nil {
				log.Warn("[EASYSS] query dns failed for",
					"server", ss.Server(), "from", ss.directDNSServer, "err", err, "retry_after(s)", i)
				time.Sleep(time.Duration(i) * time.Second)
				continue
			}
		}
		if err != nil {
			return err
		}
		if msg != nil {
			log.Info("[EASYSS] query dns success for", "server", ss.Server(), "from", ss.directDNSServer)
		}

		if msg != nil && msgAAAA != nil {
			if len(msg.Answer) > 0 {
				for _, an := range msg.Answer {
					if a, ok := an.(*dns.A); ok {
						ss.serverIP = a.A.String()
						break
					}
				}
				if ss.serverIP == "" {
					return errors.New("can't query server ip from dns")
				}
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
			log.Error("[EASYSS] get system gateway and device", "err", err.Error())
		}
		ss.localGw = gw
		ss.localDev = dev

		iface, err := net.InterfaceByName(dev)
		if err != nil {
			log.Error("[EASYSS] interface by name", "err", err)
			return err
		}
		ss.devIndex = iface.Index
	}

	return nil
}

func (ss *Easyss) InitTcpPool() error {
	if !ss.IsNativeOutboundProto() {
		log.Info("[EASYSS] outbound proto don't need init tcp pool", "proto", ss.OutboundProto())
		return nil
	}

	if ss.DisableTLS() {
		log.Info("[EASYSS] TLS is disabled")
	} else {
		log.Info("[EASYSS] TLS is enabled")
	}
	if ss.DisableUTLS() {
		log.Info("[EASYSS] uTLS is disabled")
	} else {
		log.Info("[EASYSS] uTLS is enabled")
	}
	log.Info("[EASYSS] initializing tcp pool with", "easy_server", ss.ServerAddr())

	certPool, err := ss.loadCustomCertPool()
	if err != nil {
		log.Error("[EASYSS] load custom cert pool", "err", err)
		return err
	}

	network := "tcp"
	if ss.DisableIPV6() {
		network = "tcp4"
	}
	factory := func() (net.Conn, error) {
		if ss.DisableTLS() {
			return net.DialTimeout(network, ss.ServerAddr(), ss.Timeout())
		}

		ctx, cancel := context.WithTimeout(context.Background(), ss.Timeout())
		defer cancel()
		if ss.DisableUTLS() {
			dialer := &tls.Dialer{
				Config: &tls.Config{RootCAs: certPool},
			}
			return dialer.DialContext(ctx, network, ss.ServerAddr())
		}

		conn, err := net.DialTimeout(network, ss.ServerAddr(), ss.Timeout())
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
		InitialCap:  MaxIdle,
		MaxCap:      MaxCap,
		MaxIdle:     MaxIdle,
		Idletime:    IdleTime,
		MaxLifetime: MaxLifetime,
		Factory:     factory,
	}
	tcpPool, err := easypool.NewHeapPool(config)
	ss.SetPool(tcpPool)

	return err
}

func (ss *Easyss) loadCustomCertPool() (*x509.CertPool, error) {
	caString, err := ss.loadCustomCertString()
	if err != nil || caString == "" {
		return nil, err
	}

	certPool := x509.NewCertPool()
	if ok := certPool.AppendCertsFromPEM([]byte(caString)); !ok {
		return certPool, errors.New("append certs from pem failed")
	}

	return certPool, nil
}

func (ss *Easyss) loadCustomCertString() (string, error) {
	if ss.CAPath() == "" {
		return "", nil
	}
	e, err := util.FileExists(ss.CAPath())
	if err != nil {
		log.Error("[EASYSS] lookup self-signed ca cert", "err", err)
		return "", err
	}
	if !e {
		log.Warn("[EASYSS] ca cert is set but not exists, so self-signed cert is no effect", "cert_path", ss.CAPath())
		return "", nil
	} else {
		log.Info("[EASYSS] using self-signed", "cert_path", ss.CAPath())
		caBuf, err := os.ReadFile(ss.CAPath())
		return string(caBuf), err
	}
}

func (ss *Easyss) initHTTPOutboundClient() error {
	if !ss.IsHTTPOutboundProto() && !ss.IsHTTPSOutboundProto() {
		return nil
	}

	client := req.C().
		EnableForceHTTP1().
		SetTimeout(0).
		DisableAutoReadResponse().
		SetUserAgent(UserAgent)
	client.
		SetMaxIdleConns(MaxIdle).
		SetIdleConnTimeout(MaxLifetime).
		SetMaxConnsPerHost(512).
		SetTLSHandshakeTimeout(ss.TLSTimeout())
	client.
		GetTransport().
		WrapRoundTripFunc(func(rt http.RoundTripper) req.HttpRoundTripFunc {
			return func(req *http.Request) (resp *http.Response, err error) {
				resp, err = gzhttp.Transport(rt).RoundTrip(req)
				return
			}
		})

	if ss.IsHTTPSOutboundProto() {
		cert, err := ss.loadCustomCertString()
		if err != nil {
			log.Error("[EASYSS] load custom cert string", "err", err)
			return err
		}
		if cert != "" {
			log.Info("set root cert from string", "cert", cert)
			client.SetRootCertFromString(cert)
		}
		if !ss.DisableUTLS() {
			client.SetTLSFingerprintChrome()
		}
	}

	ss.httpOutboundClient = client
	return nil
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

func (ss *Easyss) PingTimeout() time.Duration {
	timeout := ss.Timeout() / 5
	if timeout < time.Second {
		timeout = time.Second
	}
	return timeout
}

func (ss *Easyss) TLSTimeout() time.Duration {
	timeout := ss.Timeout() / 3
	if timeout < time.Second {
		timeout = time.Second
	}
	return timeout
}

func (ss *Easyss) CMDTimeout() time.Duration {
	return ss.Timeout() * 3
}

func (ss *Easyss) ReadDeadlineTimeout() time.Duration {
	return ss.Timeout() * 5
}

func (ss *Easyss) AuthUsername() string {
	return ss.config.AuthUsername
}

func (ss *Easyss) AuthPassword() string {
	return ss.config.AuthPassword
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

func (ss *Easyss) LogFilePath() string {
	return ss.config.GetLogFilePath()
}

func (ss *Easyss) DisableUTLS() bool {
	return ss.config.DisableUTLS
}

func (ss *Easyss) DisableTLS() bool {
	return ss.config.DisableTLS
}

func (ss *Easyss) DisableSysProxy() bool {
	return ss.config.DisableSysProxy
}

func (ss *Easyss) DisableIPV6() bool {
	return ss.config.DisableIPV6
}

func (ss *Easyss) EnableForwardDNS() bool {
	return ss.config.EnableForwardDNS
}

func (ss *Easyss) CAPath() string {
	return ss.config.CAPath
}

func (ss *Easyss) HTTPOutboundClient() *req.Client {
	return ss.httpOutboundClient
}

func (ss *Easyss) OutboundProto() string {
	return ss.config.OutboundProto
}

func (ss *Easyss) IsNativeOutboundProto() bool {
	return ss.config.OutboundProto == OutboundProtoNative
}

func (ss *Easyss) IsHTTPOutboundProto() bool {
	return ss.config.OutboundProto == OutboundProtoHTTP
}

func (ss *Easyss) IsHTTPSOutboundProto() bool {
	return ss.config.OutboundProto == OutboundProtoHTTPS
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

func (ss *Easyss) AvailableConn(needPingACK ...bool) (conn net.Conn, err error) {
	var pool easypool.Pool
	var tryCount int
	if ss.IsNativeOutboundProto() {
		if pool = ss.Pool(); pool == nil {
			return nil, errors.New("pool is closed")
		}
		tryCount = pool.Len() + 1
	} else {
		tryCount = MaxIdle + 1
	}

	pingTest := func(conn net.Conn) (er error) {
		var csStream net.Conn
		csStream, er = cipherstream.New(conn, ss.Password(), cipherstream.MethodAes256GCM, cipherstream.FrameTypePing)
		if er != nil {
			return er
		}

		cs := csStream.(*cipherstream.CipherStream)
		defer func() {
			if er != nil {
				cs.MarkConnUnusable()
				_ = conn.Close()
			}
			cs.Release()
		}()

		start := time.Now()
		ping := []byte(strconv.FormatInt(start.UnixNano(), 10))
		flag := cipherstream.FlagDefault
		if len(needPingACK) > 0 && needPingACK[0] {
			flag |= cipherstream.FlagNeedACK
		}
		if er = cs.WritePing(ping, flag); er != nil {
			return
		}

		return
	}

	for i := 0; i < tryCount; i++ {
		switch ss.OutboundProto() {
		case OutboundProtoHTTP:
			conn, err = httptunnel.NewLocalConn(ss.HTTPOutboundClient(), "http://"+ss.ServerAddr())
		case OutboundProtoHTTPS:
			conn, err = httptunnel.NewLocalConn(ss.HTTPOutboundClient(), "https://"+ss.ServerAddr())
		default:
			conn, err = pool.Get()
		}
		if err != nil {
			log.Warn("[EASYSS] get conn failed", "err", err)
			continue
		}

		err = pingTest(conn)
		if err != nil {
			log.Warn("[EASYSS] ping easyss-server", "err", err)
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

func (ss *Easyss) TunConfig() *TunConfig {
	return ss.config.TunConfig
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
	a, err1 := util.DNSMsgTypeA(dnsServer, domain)
	aaaa, err2 := util.DNSMsgTypeAAAA(dnsServer, domain)

	return a, aaaa, errors.Join(err1, err2)
}

func (ss *Easyss) MatchHostRule(host string) HostRule {
	if ss.ProxyRule() == ProxyRuleDirect || ss.IsLANHost(host) {
		return HostRuleDirect
	}
	if ss.ProxyRule() == ProxyRuleProxy {
		return HostRuleProxy
	}
	if ss.HostMatchCustomDirectConfig(host) {
		return HostRuleDirect
	}

	if ss.ProxyRule() == ProxyRuleAutoBlock && !util.IsIP(host) {
		if ss.geoSiteDirect.SimpleMatch(host, false) {
			return HostRuleDirect
		}
		if ss.geoSiteBlock.SimpleMatch(host, true) {
			return HostRuleBlock
		}
	}

	if ss.ProxyRule() == ProxyRuleReverseAuto && !ss.HostAtCN(host) {
		return HostRuleDirect
	}
	if ss.HostAtCN(host) {
		return HostRuleDirect
	}

	return HostRuleProxy
}

func (ss *Easyss) HostMatchCustomDirectConfig(host string) bool {
	if util.IsIP(host) {
		if _, ok := ss.customDirectIPs[host]; ok {
			return true
		}
		for _, v := range ss.customDirectCIDRIPs {
			if v.Contains(net.ParseIP(host)) {
				return true
			}
		}
	} else {
		if _, ok := ss.customDirectDomains[host]; ok {
			return true
		}
		subs := subDomains(host)
		for _, sub := range subs {
			if _, ok := ss.customDirectDomains[sub]; ok {
				return true
			}
		}
	}
	return false
}

func (ss *Easyss) HostAtCN(host string) bool {
	if host == "" {
		return false
	}

	if util.IsIP(host) {
		return ss.IPAtCN(host)
	}
	// if the host end with .cn, return true
	if strings.HasSuffix(host, ".cn") {
		return true
	}

	return ss.geoSiteDirect.FullMatch(host)
}

func (ss *Easyss) IPAtCN(ip string) bool {
	_ip := net.ParseIP(ip)
	if _ip == nil {
		return false
	}
	country, err := ss.geoIPDB.Country(_ip)
	if err != nil {
		return false
	}

	if country.Country.IsoCode == "CN" {
		return true
	}

	return false
}

func (ss *Easyss) IsLANHost(host string) bool {
	if host == "localhost" {
		return true
	}

	return util.IsLANIP(host)
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
