package main

import (
	"net"
	"strconv"
	"time"

	"github.com/nange/easyss/cipherstream"
	log "github.com/sirupsen/logrus"
)

func tcpRemote(config *Config) {
	listenAddr := ":" + strconv.Itoa(config.ServerPort)
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatal(err)
	}
	log.Infof("starting remote socks5 server at %v ...", listenAddr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Error("accept:", err)
			continue
		}
		conn.(*net.TCPConn).SetKeepAlive(true)
		conn.(*net.TCPConn).SetKeepAlivePeriod(30 * time.Second)

		go func() {
			defer conn.Close()

			gcm, err := cipherstream.NewAes256GCM([]byte(config.Password))
			if err != nil {
				log.Errorf("cipherstream.NewAes256GCM err:%+v", err)
				return
			}

			buf := make([]byte, 3+1+1+4+1+257+gcm.NonceSize()+gcm.Overhead())
			conn.Read(buf)

		}()

	}
}
