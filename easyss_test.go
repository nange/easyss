package easyss

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/coocood/freecache"
	"github.com/oschwald/geoip2-golang"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"golang.org/x/net/proxy"
)

const (
	CACert = `-----BEGIN CERTIFICATE-----
MIIB1DCCAXqgAwIBAgIULPyfQyUssIDTxsGLzQJx6w5rbukwCgYIKoZIzj0EAwIw
SDELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1TYW4gRnJhbmNp
c2NvMRQwEgYDVQQDEwtlYXN5LWNhLm5ldDAeFw0yNDAyMTgwNzA1MDBaFw0yOTAy
MTYwNzA1MDBaMEgxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDQTEWMBQGA1UEBxMN
U2FuIEZyYW5jaXNjbzEUMBIGA1UEAxMLZWFzeS1jYS5uZXQwWTATBgcqhkjOPQIB
BggqhkjOPQMBBwNCAAT71NO1p1yANOG7AkEe1bQvcQp6fNgRRqvwrC/cIGp6bDqt
H3klE8D22g5upORqkETrqlKeqi0UxflAUD9RSh7Ro0IwQDAOBgNVHQ8BAf8EBAMC
AQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU8pqT0wmFdRQ6gxX+ZWAWhMon
fIQwCgYIKoZIzj0EAwIDSAAwRQIhAO3ZLMAh8nlR2cJbecUZJ51GbBbLny5CdcN7
CbTHmkaiAiB+LABnNKD+O0P+UPidt+nBpo+2u1/W7wtQvKJcFVl+mQ==
-----END CERTIFICATE-----
`
	ServerCert = `-----BEGIN CERTIFICATE-----
MIICIDCCAcagAwIBAgIUPMWIWsDwAl4fIpDSHDbPAS/YX2MwCgYIKoZIzj0EAwIw
SDELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1TYW4gRnJhbmNp
c2NvMRQwEgYDVQQDEwtlYXN5LWNhLm5ldDAgFw0yNDAyMTgwNzA3MDBaGA8yMTI0
MDEyNTA3MDcwMFowTDELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQH
Ew1TYW4gRnJhbmNpc2NvMRgwFgYDVQQDEw9lYXN5LXNlcnZlci5uZXQwWTATBgcq
hkjOPQIBBggqhkjOPQMBBwNCAATaBuIN8NmDmSMmSpXbNp2pzqIjTtyvccgEGTdx
TbtWF2YvqqwmQY/fPDyRDp1hCq2toD1wCEjCXOJx5BaF1n8Wo4GHMIGEMA4GA1Ud
DwEB/wQEAwIFoDATBgNVHSUEDDAKBggrBgEFBQcDATAMBgNVHRMBAf8EAjAAMB0G
A1UdDgQWBBSnOwxAIjDEYPp88Ooed4HWL9r8bTAfBgNVHSMEGDAWgBTympPTCYV1
FDqDFf5lYBaEyid8hDAPBgNVHREECDAGhwR/AAABMAoGCCqGSM49BAMCA0gAMEUC
IGphTgfgOgRRGIqDX/ByZx33QUh6P+nRSPyMPLV24nDGAiEAl0I45LBWXopCzDLD
ftJgQof/GMr8+pMLn0UM/Xv5xec=
-----END CERTIFICATE-----
`
	ServerKey = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIO8NZoPnbSD3NL9PmL9zMz/OUvFuwYVGzzicctyWbf57oAoGCCqGSM49
AwEHoUQDQgAE2gbiDfDZg5kjJkqV2zadqc6iI07cr3HIBBk3cU27VhdmL6qsJkGP
3zw8kQ6dYQqtraA9cAhIwlziceQWhdZ/Fg==
-----END EC PRIVATE KEY-----
`
)

const (
	Server     = "127.0.0.1"
	Password   = "test-pass"
	ServerPort = 9999
	LocalPort  = 4567
	Method     = "aes-256-gcm"
)

const (
	TestHTTPSURL = "https://cloud.tencent.com"
	TestHTTPURL  = "http://cloud.tencent.com"
)

const (
	CloseWriteServerPort = "8888"
)

func TestEasyss(t *testing.T) {
	suite.Run(t, new(EasyssSuite))
}

type EasyssSuite struct {
	suite.Suite
	certPath string
	keyPath  string
	caPath   string
	tempDir  string
	ss       *Easyss
	server   *EasyServer
}

func (es *EasyssSuite) SetupTest() {
	tempDir := es.T().TempDir()
	certPath := filepath.Join(tempDir, "cert.pem")
	err := os.WriteFile(certPath, []byte(ServerCert), os.ModePerm)
	es.Require().Nil(err)
	keyPath := filepath.Join(tempDir, "key.pem")
	err = os.WriteFile(keyPath, []byte(ServerKey), os.ModePerm)
	es.Require().Nil(err)

	caPath := filepath.Join(tempDir, "ca.pem")
	err = os.WriteFile(caPath, []byte(CACert), os.ModePerm)
	es.Require().Nil(err)
	es.caPath = caPath

	es.tempDir = tempDir
	es.certPath = certPath
	es.keyPath = keyPath
}

func (es *EasyssSuite) BeforeTest(suiteName, testName string) {
	serverConfig := &ServerConfig{
		Server:     Server,
		ServerPort: ServerPort,
		Password:   Password,
		CertPath:   es.certPath,
		KeyPath:    es.keyPath,
	}
	serverConfig.SetDefaultValue()
	server, err := NewServer(serverConfig)
	es.Nil(err)
	server.disableValidateAddr = true
	es.server = server

	config := &Config{
		Server:     Server,
		ServerPort: ServerPort,
		LocalPort:  LocalPort,
		Password:   Password,
		Method:     Method,
		ProxyRule:  "proxy",
		CAPath:     es.caPath,
	}
	config.SetDefaultValue()

	switch testName {
	case "TestDisableTLS":
		serverConfig.DisableTLS = true
		config.DisableTLS = true
	case "TestHTTPTunnelOutbound":
		serverConfig.EnableHTTPInbound = true
		config.OutboundProto = "https"
		config.ServerPort = ServerPort + 1000
	}

	go es.server.Start()
	time.Sleep(time.Second)

	ss, err := New(config)
	es.Nilf(err, "New Easyss failed")
	ss.disableValidateAddr = true
	es.ss = ss

	go es.ss.LocalSocks5()
	time.Sleep(time.Second)
	go es.ss.LocalHttp()
	time.Sleep(time.Second)
}

func (es *EasyssSuite) TearDownTest() {
	es.ss.Close()
	es.server.Close()
}

func (es *EasyssSuite) TestEasySuit() {
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: func(*http.Request) (*url.URL, error) {
				return url.Parse(es.ss.Socks5ProxyAddr()) // test socks5 proxy
			},
			TLSHandshakeTimeout: 5 * time.Second,
			ForceAttemptHTTP2:   true,
			MaxConnsPerHost:     1,
		},
	}
	body, err := clientGet(client, TestHTTPSURL)
	es.Require().Nilf(err, "http get %s failed:%s", TestHTTPSURL, err)
	es.Greater(len(body), 1000)

	client2 := &http.Client{
		Transport: &http.Transport{
			Proxy: func(*http.Request) (*url.URL, error) {
				return url.Parse(fmt.Sprintf("http://%s", es.ss.LocalHttpAddr())) // test http proxy
			},
			TLSHandshakeTimeout: 5 * time.Second,
			ForceAttemptHTTP2:   true,
			MaxConnsPerHost:     1,
		},
	}
	body2, err2 := clientGet(client2, TestHTTPSURL)
	es.Require().Nilf(err2, "http get %s failed", TestHTTPSURL)
	es.Greater(len(body2), 1000)

	body3, err3 := clientGet(client2, TestHTTPURL)
	es.Require().Nilf(err3, "http get %s failed", TestHTTPURL)
	es.Greater(len(body3), 1000)
}

func (es *EasyssSuite) TestCloseWrite() {
	go closeWriteServer()
	time.Sleep(time.Second)

	msg := "hello"
	ret := closeWriteClient(msg)
	es.Equal(msg, ret)
}

func (es *EasyssSuite) TestDisableTLS() {
	es.TestEasySuit()
}

func (es *EasyssSuite) TestHTTPTunnelOutbound() {
	es.TestEasySuit()
}

func clientGet(client *http.Client, url string) (body []byte, err error) {
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}

	return io.ReadAll(resp.Body)
}

func closeWriteServer() {
	lis, err := net.Listen("tcp", ":"+CloseWriteServerPort)
	if err != nil {
		panic(err)
	}
	for {
		conn, err := lis.Accept()
		if err != nil {
			fmt.Println("accept:", err.Error())
			break
		}
		go handleConn(conn)
	}
}

func handleConn(conn net.Conn) {
	defer conn.Close()

	for {
		b := make([]byte, 1024)
		nr, err := conn.Read(b)
		if err != nil {
			fmt.Println("read:", err.Error())
			if nr > 0 {
				fmt.Println("read err, bug got:", b[:nr])
			}
			return
		}
		fmt.Println("read:", string(b[:nr]))
		time.Sleep(6 * time.Second)
		if _, err := conn.Write(b[:nr]); err != nil {
			fmt.Println("write to remote:", err.Error())
		}
	}
}

func closeWriteClient(msg string) string {
	dialer, err := proxy.SOCKS5("tcp", "127.0.0.1:"+strconv.FormatInt(LocalPort, 10), nil, proxy.Direct)
	if err != nil {
		panic("create socks5 dialer:" + err.Error())
	}
	conn, err := dialer.Dial("tcp", "127.0.0.1:"+CloseWriteServerPort)
	if err != nil {
		panic("dial:" + err.Error())
	}
	defer conn.Close()

	if _, err := conn.Write([]byte(msg)); err != nil {
		panic("write greeting message to remote:" + err.Error())
	}

	if err := conn.(*net.TCPConn).CloseWrite(); err != nil {
		panic("close write:" + err.Error())
	}

	ret := make([]byte, 1024)
	nr, err := conn.Read(ret)
	if err != nil {
		fmt.Println("read from remote:", err.Error())
		if nr > 0 {
			fmt.Println("read from remote:", string(ret[:nr]))
		}
		return ""
	}
	return string(ret[:nr])
}

func getEasyssForBench(config *Config) *Easyss {
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
	ss.geoIPDB = db
	ss.geoSiteDirect = NewGeoSite(geoSiteDirect)
	ss.geoSiteBlock = NewGeoSite(geoSiteBlock)

	if err := ss.loadCustomIPDomains(); err != nil {
		panic(err)
	}

	return ss
}

func TestSubDomains(t *testing.T) {
	domain := "as1.m.hao123.com"
	subs := subDomains(domain)
	assert.Equal(t, []string{"m.hao123.com", "hao123.com"}, subs)
}

func BenchmarkEasyss_MatchHostRule_Block(b *testing.B) {
	host := "googleads.g.doubleclick.net"

	config := &Config{ProxyRule: "auto_block"}
	config.SetDefaultValue()
	ss := getEasyssForBench(config)

	assert.Equal(b, HostRuleBlock, ss.MatchHostRule(host))

	for i := 0; i < b.N; i++ {
		ss.MatchHostRule(host)
	}
}

func BenchmarkEasyss_MatchHostRule_Direct(b *testing.B) {
	host := "baidu.com"

	config := &Config{ProxyRule: "auto_block"}
	config.SetDefaultValue()
	ss := getEasyssForBench(config)

	assert.Equal(b, HostRuleDirect, ss.MatchHostRule(host))

	for i := 0; i < b.N; i++ {
		ss.MatchHostRule(host)
	}
}

func BenchmarkEasyss_MatchHostRule_Proxy(b *testing.B) {
	host := "google.com"

	config := &Config{ProxyRule: "auto_block"}
	config.SetDefaultValue()
	ss := getEasyssForBench(config)

	assert.Equal(b, HostRuleProxy, ss.MatchHostRule(host))

	for i := 0; i < b.N; i++ {
		ss.MatchHostRule(host)
	}
}
