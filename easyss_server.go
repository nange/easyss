package easyss

import (
	"crypto/tls"
	"net"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/nange/easyss/v2/httptunnel"
	"github.com/txthinking/socks5"
)

type EasyServer struct {
	config           *ServerConfig
	mu               sync.Mutex
	ln               net.Listener
	httpTunnelServer *httptunnel.Server
	tlsConfig        *tls.Config

	// it will only be init if 'next_proxy_url' in config is not empty
	nextProxyS5Cli *socks5.Client

	// only used for testing
	disableValidateAddr bool
}

func NewServer(config *ServerConfig) *EasyServer {
	es := &EasyServer{config: config}

	if u := es.NextProxyURL(); u != nil {
		if u.Scheme == "socks5" {
			es.nextProxyS5Cli, _ = socks5.NewClient(u.Host, "", "", 0, 0)
		}
	}

	return es
}

func (es *EasyServer) Server() string {
	return es.config.Server
}

func (es *EasyServer) ListenAddr() string {
	addr := ":" + strconv.Itoa(es.ServerPort())
	return addr
}

func (es *EasyServer) ListenHTTPTunnelAddr() string {
	addr := ":" + strconv.Itoa(es.HTTPInboundPort())
	return addr
}

func (es *EasyServer) DisableUTLS() bool {
	return es.config.DisableUTLS
}

func (es *EasyServer) DisableTLS() bool {
	return es.config.DisableTLS
}

func (es *EasyServer) ServerPort() int {
	return es.config.ServerPort
}

func (es *EasyServer) Password() string {
	return es.config.Password
}

func (es *EasyServer) Timeout() time.Duration {
	return time.Duration(es.config.Timeout) * time.Second
}

func (es *EasyServer) CertPath() string {
	return es.config.CertPath
}

func (es *EasyServer) KeyPath() string {
	return es.config.KeyPath
}

func (es *EasyServer) EnabledHTTPInbound() bool {
	return es.config.EnableHTTPInbound
}

func (es *EasyServer) HTTPInboundPort() int {
	return es.config.HTTPInboundPort
}

func (es *EasyServer) NextProxyURL() *url.URL {
	if es.config.NextProxyURL == "" {
		return nil
	}
	u, _ := url.Parse(es.config.NextProxyURL)
	return u
}

func (es *EasyServer) NextProxyUDP() bool {
	return es.config.NextProxyUDP
}

func (es *EasyServer) Close() (err error) {
	es.mu.Lock()
	defer es.mu.Unlock()
	if es.ln != nil {
		err = es.ln.Close()
	}
	if es.httpTunnelServer != nil {
		err = es.httpTunnelServer.Close()
	}
	return
}
