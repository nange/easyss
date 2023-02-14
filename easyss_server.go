package easyss

import (
	"net"
	"sync"
	"time"
)

type EasyServer struct {
	config *ServerConfig
	mu     sync.Mutex
	ln     net.Listener

	// only used for testing
	disableValidateAddr bool
}

func NewServer(config *ServerConfig) *EasyServer {
	return &EasyServer{config: config}
}

func (es *EasyServer) Server() string {
	return es.config.Server
}

func (es *EasyServer) DisableUTLS() bool {
	return es.config.DisableUTLS
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

func (es *EasyServer) Close() error {
	es.mu.Lock()
	defer es.mu.Unlock()
	if es.ln != nil {
		return es.ln.Close()
	}
	return nil
}
