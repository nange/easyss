package main

import (
	"io"
	"net"
	"strconv"
	"time"

	"github.com/nange/easyss/cipherstream"
	"github.com/nange/easyss/socks"
	"github.com/nange/easyss/utils"
	"github.com/pkg/errors"
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
			_, err = io.ReadFull(conn, buf)
			if err != nil {
				log.Errorf("io.ReadFull err:%+v", errors.WithStack(err))
				return
			}

			dataframe, err := gcm.Decrypt(buf)
			if err != nil {
				log.Errorf("gcm.Decrypt err:%+v", err)
				return
			}

			addrbytes, err := utils.GetAddrFromHTTP2DataFrame(dataframe)
			if err != nil {
				log.Errorf("utils.GetAddrFromHTTP2DataFrame err:%+v", err)
				return
			}

			addr := socks.Addr(addrbytes)
			log.Info("target addr is:%v", addr.String())

		}()

	}
}
