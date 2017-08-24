package main

import (
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	"github.com/nange/easyss/cipherstream"
	"github.com/nange/easyss/socks"
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

			addr, err := getTargetAddr(conn, config.Password)
			if err != nil {
				log.Errorf("get target addr err:%+v", err)
				return
			}
			log.Debugf("target proxy addr is:%v", addr.String())

			tconn, err := net.Dial("tcp", addr.String())
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
				n, err := io.Copy(csConn, tconn)
				log.Warnf("reciveve %v bytes from %v, err:%v", n, addr, err)
			}()
			n, err := io.Copy(tconn, csConn)
			log.Warnf("send %v bytes to %v, err:%v", n, addr, err)
		}()

	}
}

func getTargetAddr(conn net.Conn, password string) (addr socks.Addr, err error) {
	gcm, err := cipherstream.NewAes256GCM([]byte(password))
	if err != nil {
		return
	}

	headerbuf := make([]byte, 9+gcm.NonceSize()+gcm.Overhead())
	if _, err = io.ReadFull(conn, headerbuf); err != nil {
		err = errors.WithStack(err)
		return
	}

	headerplain, err := gcm.Decrypt(headerbuf)
	if err != nil {
		log.Debugf("gcm.Decrypt decrypt headerbuf:%v, err:%+v", headerbuf, err)
		return
	}

	payloadlen := int(headerplain[0])<<16 | int(headerplain[1])<<8 | int(headerplain[2])
	if headerplain[3] != 0x0 || headerplain[4] != 0x0 {
		err = errors.WithStack(errors.New(fmt.Sprintf("http2 data frame type:%v is invalid or flag:%v is invalid, both should be 0x0",
			headerplain[3], headerplain[4])))
		return
	}

	payloadbuf := make([]byte, payloadlen+gcm.NonceSize()+gcm.Overhead())
	if _, err = io.ReadFull(conn, payloadbuf); err != nil {
		err = errors.WithStack(err)
		log.Debugf("io.ReadFull read payloadbuf err:%+v, len:%v", err, len(payloadbuf))
		return
	}

	payloadplain, err := gcm.Decrypt(payloadbuf)
	if err != nil {
		log.Debugf("gcm.Decrypt decrypt payloadbuf:%v, err:%+v", payloadbuf, err)
		return
	}

	return payloadplain, nil
}
