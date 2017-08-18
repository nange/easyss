package main

import (
	"net"
	"strconv"
	"time"

	"github.com/nange/easyss/cipherstream"
	"github.com/nange/easyss/socks"
	"github.com/nange/easyss/utils"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

func tcpLocal(config *Config) {
	listenAddr := ":" + strconv.Itoa(config.LocalPort)
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatal(err)
	}
	log.Infof("starting local socks5 server at %v ...", listenAddr)

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

			addr, err := socks.HandShake(conn)
			if err != nil {
				log.Errorf("local handshake err:%+v, remote:%v", err, addr)
				return
			}
			rconn, err := net.Dial("tcp", config.Server+":"+strconv.Itoa(config.ServerPort))
			if err != nil {
				log.Error("net.Dial err:%v, server:%v, port:%v", err, config.Server, config.ServerPort)
				return
			}
			defer rconn.Close()

			rconn.(*net.TCPConn).SetKeepAlive(true)
			rconn.(*net.TCPConn).SetKeepAlivePeriod(30 * time.Second)

			dataframe := utils.NewHTTP2DataFrame(addr)

			gcm, err := cipherstream.NewAes256GCM([]byte(config.Password))
			if err != nil {
				log.Errorf("cipherstream.NewAes256GCM err:%+v", err)
				return
			}

			ciphertext, err := gcm.Encrypt(dataframe)
			if err != nil {
				log.Errorf("gcm.Encrypt err:%+v", err)
				return
			}

			_, err = rconn.Write(ciphertext)
			if err != nil {
				log.Errorf("rconn.Write err:%+v", errors.WithStack(err))
				return
			}
		}()

	}
}
