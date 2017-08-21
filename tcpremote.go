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

			addr := socks.Addr(addrbytes).String()
			log.Infof("target addr is:%v", addr)

			tconn, err := net.Dial("tcp", addr)
			if err != nil {
				log.Errorf("net.Dial %v err:%v", addr, err)
				return
			}
			defer tconn.Close()

			csConn, err := cipherstream.New(conn, config.Password, config.Method)
			if err != nil {
				log.Errorf("new cipherstream err:%+v, password:%v, method:%v",
					err, config.Password, config.Method)
				return
			}

			go func() {
				n, err := cipherstream.Copy(csConn, tconn)
				log.Warnf("reciveve %v bytes from %v, err:%+v", n, addr, err)
			}()
			n, err := cipherstream.Copy(tconn, csConn)
			log.Warnf("send %v bytes to %v, err:%+v", n, addr, err)
		}()

	}
}
