package easyss

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
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

func TestEasyss(t *testing.T) {
	suite.Run(t, new(EasyssSuite))
}

type EasyssSuite struct {
	suite.Suite
	ss     *Easyss
	server *EasyServer
}

func (es *EasyssSuite) SetupSuite() {
	tempDir := es.T().TempDir()
	certPath := filepath.Join(tempDir, "cert.pem")
	err := os.WriteFile(certPath, []byte(ServerCert), os.ModePerm)
	es.Require().Nil(err)
	keyPath := filepath.Join(tempDir, "key.pem")
	err = os.WriteFile(keyPath, []byte(ServerKey), os.ModePerm)
	es.Require().Nil(err)

	server := NewServer(&ServerConfig{
		Server:     Server,
		ServerPort: ServerPort,
		Password:   Password,
		CertPath:   certPath,
		KeyPath:    keyPath,
	})
	es.server = server

	go es.server.Start()
	time.Sleep(time.Second)

	caPath := filepath.Join(tempDir, "ca.pem")
	err = os.WriteFile(caPath, []byte(CACert), os.ModePerm)
	es.Require().Nil(err)

	config := &Config{
		Server:     Server,
		ServerPort: ServerPort,
		LocalPort:  LocalPort,
		Password:   Password,
		Method:     Method,
		CAPath:     caPath,
	}
	config.SetDefaultValue()
	ss, err := New(config)
	es.Nilf(err, "New Easyss failed")
	es.ss = ss

	es.Nilf(ss.InitTcpPool(), "init tcp pool failed")
	go ss.LocalSocks5()
	go ss.LocalHttp()
	time.Sleep(time.Second)
}

func (es *EasyssSuite) TearDownSuite() {
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
	es.Require().Nilf(err, "http get baidu.com failed")
	es.T().Logf("body:%v", string(body))
	es.Greater(len(body), 100)

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
	es.T().Logf("body2:%v", string(body2))
	es.Greater(len(body2), 100)

	body3, err3 := clientGet(client2, "http://www.baidu.com")
	es.Require().Nilf(err3, "http get baidu.com failed")
	es.T().Logf("body3:%v", string(body3))
	es.Greater(len(body3), 100)
}

func clientGet(client *http.Client, url string) (body []byte, err error) {
	resp, err := client.Get(url)
	if resp.Body != nil {
		defer resp.Body.Close()
	}

	return io.ReadAll(resp.Body)
}
