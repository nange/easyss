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
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
	"golang.org/x/net/proxy"
)

const (
	CACert = `-----BEGIN CERTIFICATE-----
MIIB0zCCAXqgAwIBAgIUQpfWM7Pf3xfd48CjLuzz7cVH1p0wCgYIKoZIzj0EAwIw
SDELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1TYW4gRnJhbmNp
c2NvMRQwEgYDVQQDEwtlYXN5LWNhLm5ldDAeFw0yMzAyMTAwNjEyMDBaFw0yODAy
MDkwNjEyMDBaMEgxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDQTEWMBQGA1UEBxMN
U2FuIEZyYW5jaXNjbzEUMBIGA1UEAxMLZWFzeS1jYS5uZXQwWTATBgcqhkjOPQIB
BggqhkjOPQMBBwNCAAQh7ZlVfd/w0q6sl/7kv5D5mh7mnncSzGXxDImePFAKOwJM
WLqcjBuR2KjrPHe0Z5RRFDyw5K/b4SkpH60/LSASo0IwQDAOBgNVHQ8BAf8EBAMC
AQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUSUFRL9l3qRcQ9pgXD/z3cAo5
jMowCgYIKoZIzj0EAwIDRwAwRAIgJOT49coPZEIicTu99SMeDhSL6DiPtIK01gKv
J9U0t5QCIG3Tq5QQA6JNBeI2EXKLdGysNTbTHd0vU21RA/AsC1Gf
-----END CERTIFICATE-----
`
	ServerCert = `-----BEGIN CERTIFICATE-----
MIICHzCCAcSgAwIBAgIUBiAN1AieuYSsOcUZuEaQJiHLXfIwCgYIKoZIzj0EAwIw
SDELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1TYW4gRnJhbmNp
c2NvMRQwEgYDVQQDEwtlYXN5LWNhLm5ldDAeFw0yMzAyMTAwNjI4MDBaFw0yNDAy
MTAwNjI4MDBaMEwxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDQTEWMBQGA1UEBxMN
U2FuIEZyYW5jaXNjbzEYMBYGA1UEAxMPZWFzeS1zZXJ2ZXIubmV0MFkwEwYHKoZI
zj0CAQYIKoZIzj0DAQcDQgAEE2xalubHlSGBOqhEGVwyFLvtqX/kQKbQMsfmh5Sb
Q0RbvsxYSK8vh6PTQswQhJQNVZnCnRWtMWjsJUJ6ZMhGfaOBhzCBhDAOBgNVHQ8B
Af8EBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDAYDVR0TAQH/BAIwADAdBgNV
HQ4EFgQU6kEu8J3rKg7WDuIAYh7eA7ahqN8wHwYDVR0jBBgwFoAUSUFRL9l3qRcQ
9pgXD/z3cAo5jMowDwYDVR0RBAgwBocEfwAAATAKBggqhkjOPQQDAgNJADBGAiEA
wuJM0JP0qdABYbFoA6FIzhYD9WzB5URFmmSbAAP5tm0CIQDW9tD/ZGNuPR/ffvJz
4/FG9UAjoLqailzsSRkl2lNTiQ==
-----END CERTIFICATE-----
`
	ServerKey = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIOT62e0IzVre+nFD7YuRm34I5urU7ZRF3EAee049n4xgoAoGCCqGSM49
AwEHoUQDQgAEE2xalubHlSGBOqhEGVwyFLvtqX/kQKbQMsfmh5SbQ0RbvsxYSK8v
h6PTQswQhJQNVZnCnRWtMWjsJUJ6ZMhGfQ==
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
	server := NewServer(serverConfig)
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

	es.Nilf(es.ss.InitTcpPool(), "init tcp pool failed")
	go es.ss.LocalSocks5()
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
	body, err := clientGet(client, "https://baidu.com")
	es.Require().Nilf(err, "http get baidu.com failed:%s", err)
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
	body2, err2 := clientGet(client2, "https://baidu.com")
	es.Require().Nilf(err2, "http get baidu.com failed")
	es.Greater(len(body2), 1000)

	body3, err3 := clientGet(client2, "http://www.baidu.com")
	es.Require().Nilf(err3, "http get baidu.com failed")
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
