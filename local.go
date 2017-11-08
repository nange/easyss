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

func (ss *Easyss) Local() {
	listenAddr := ":" + strconv.Itoa(ss.config.LocalPort)
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatal(err)
	}
	log.Infof("starting local socks5 server at %v", listenAddr)
	log.Debugf("config:%v", *ss.config)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Error("accept:", err)
			continue
		}
		conn.(*net.TCPConn).SetKeepAlive(true)
		conn.(*net.TCPConn).SetKeepAlivePeriod(10 * time.Second)

		go func() {
			defer conn.Close()

			addr, err := socks.HandShake(conn)
			if err != nil {
				log.Errorf("local handshake err:%+v, remote:%v", err, addr)
				return
			}
			log.Debugf("target proxy addr is:%v", addr.String())

			var stream io.ReadWriteCloser
			if ss.config.EnableQuic {
				stream, err = ss.getStream()
			} else {
				stream, err = net.Dial("tcp", ss.config.Server+":"+strconv.Itoa(ss.config.ServerPort))
			}
			if err != nil {
				log.Errorf("get stream err:%+v", err)
				return
			}
			defer stream.Close()

			header, payload := utils.NewHTTP2DataFrame(addr)
			gcm, err := cipherstream.NewAes256GCM([]byte(ss.config.Password))
			if err != nil {
				log.Errorf("cipherstream.NewAes256GCM err:%+v", err)
				return
			}

			headercipher, err := gcm.Encrypt(header)
			if err != nil {
				log.Errorf("gcm.Encrypt err:%+v", err)
				return
			}
			_, err = stream.Write(headercipher)
			if err != nil {
				log.Errorf("stream.Write err:%+v", errors.WithStack(err))
				return
			}

			payloadcipher, err := gcm.Encrypt(payload)
			if err != nil {
				log.Errorf("gcm.Encrypt err:%+v", err)
				return
			}
			_, err = stream.Write(payloadcipher)
			if err != nil {
				log.Errorf("stream.Write err:%+v", errors.WithStack(err))
				return
			}

			csStream, err := cipherstream.New(stream, ss.config.Password, ss.config.Method)
			if err != nil {
				log.Errorf("new cipherstream err:%+v, password:%v, method:%v",
					err, ss.config.Password, ss.config.Method)
				return
			}

			go func() {
				defer conn.Close()
				defer stream.Close()
				n, err := io.Copy(conn, csStream)
				log.Infof("reciveve %v bytes from %v, message:%v", n, addr.String(), err)
			}()
			n, err := io.Copy(csStream, conn)
			log.Infof("send %v bytes to %v, message:%v", n, addr.String(), err)
		}()

	}
}
