package easyss

import (
	"crypto/tls"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/nange/easyss/v2/httptunnel"
)

type EasyServer struct {
	config           *ServerConfig
	mu               sync.Mutex
	ln               net.Listener
	httpTunnelServer *httptunnel.Server
	tlsConfig        *tls.Config

	// only used for testing
	disableValidateAddr bool
}

func NewServer(config *ServerConfig) *EasyServer {
	return &EasyServer{config: config}
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
