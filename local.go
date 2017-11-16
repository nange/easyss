package main

import (
	"io"
	"net"
	"strconv"
	"time"

	"github.com/nange/easypool"
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
				stream, err = ss.tcpPool.Get()
			}
			if err != nil {
				log.Errorf("get stream err:%+v", err)
				return
			}
			defer stream.Close()

			header := utils.NewHTTP2DataFrameHeader(len(addr))
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

			payloadcipher, err := gcm.Encrypt([]byte(addr))
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

			n1, n2, needclose := relay(csStream, conn, true)
			log.Infof("send %v bytes to %v, and recive %v bytes, needclose:%v", n1, addr, n2, needclose)
		}()
	}
}

// relay copies between cipherstream and plaintxtstream.
// return the number of bytes copies
// from plaintxtstream to cipherstream, from cipherstream to plaintxtstream, and any error occurred.
func relay(cipher, plaintxt io.ReadWriteCloser, islocal bool) (int64, int64, bool) {
	needclose := false
	ch := make(chan int64)

	go func() {
		n, err := io.Copy(plaintxt, cipher)
		if err == cipherstream.ErrDecrypt || err == cipherstream.ErrReadCipher {
			log.Warnf("io.Copy err:%+v, maybe underline connection have been closed", err)
			if cs, ok := cipher.(*cipherstream.CipherStream); ok {
				if pc, ok := cs.ReadWriteCloser.(*easypool.PoolConn); ok {
					log.Debug("mark cipher stream unusable")
					pc.MarkUnusable()
					needclose = true
				}
			}
		}
		if conn, ok := plaintxt.(*net.TCPConn); ok {
			log.Debugf("set tcp connection deadline to now, and free other goroutine")
			conn.SetDeadline(time.Now()) // wake up the other goroutine blocking on plaintxt conn
		}
		ch <- n
	}()

	n1, err := io.Copy(cipher, plaintxt)
	if err == cipherstream.ErrEncrypt || err == cipherstream.ErrWriteCipher {
		log.Warnf("io.Copy err:%+v, maybe underline connection have been closed", err)
		if cs, ok := cipher.(*cipherstream.CipherStream); ok {
			if pc, ok := cs.ReadWriteCloser.(*easypool.PoolConn); ok {
				log.Debug("mark cipher stream unusable")
				pc.MarkUnusable()
				needclose = true
			}
		}
	}
	if conn, ok := plaintxt.(*net.TCPConn); ok {
		log.Debugf("set tcp connection deadline to now, and free other goroutine")
		conn.SetDeadline(time.Now()) // wake up the other goroutine blocking on plaintxt conn
	}
	n2 := <-ch

	if islocal {
		if cs, ok := cipher.(*cipherstream.CipherStream); ok {
			if pc, ok := cs.ReadWriteCloser.(*easypool.PoolConn); ok {
				if pc.IsUnusable() {
					log.Debug("write RST_STREAM to remote server")
					rstHeader := utils.NewHTTP2RstStreamHeader()
					cipher.Write(rstHeader)
				}
			}
		}
	}

	return n1, n2, needclose
}
