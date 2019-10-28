package easyss

import (
	"io"
	"net"
	"strconv"
	"time"

	"github.com/nange/easypool"
	"github.com/nange/easyss/cipherstream"
	"github.com/nange/easyss/socks"
	"github.com/nange/easyss/util"
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
		conn.(*net.TCPConn).SetKeepAlivePeriod(time.Duration(ss.config.Timeout) * time.Second)

		addr, cmd, err := socks.HandShake(conn)
		if err != nil {
			log.Warnf("local handshake err:%+v, remote:%v", err, addr)
			continue
		}
		if cmd == socks.CmdUDPAssociate {
			log.Infof("current request is for CmdUDPAssociate")
			time.Sleep(10 * time.Second)
			return
		}
		log.Infof("target proxy addr is:%v", addr)

		go ss.localRelay(conn, addr)
	}
}

func (ss *Easyss) localRelay(localConn net.Conn, addr string) (err error) {
	defer localConn.Close()

	var stream io.ReadWriteCloser
	stream, err = ss.tcpPool.Get()
	log.Infof("after pool get: current tcp pool have %v connections", ss.tcpPool.Len())
	defer log.Infof("after stream close: current tcp pool have %v connections", ss.tcpPool.Len())

	if err != nil {
		log.Errorf("get stream err:%+v", err)
		return
	}
	defer stream.Close()

	header := util.NewHTTP2DataFrameHeader(len(addr) + 1)
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
	ciphermethod := EncodeCipherMethod(ss.config.Method)
	if ciphermethod == 0 {
		log.Errorf("unsupported cipher method:%+v", ss.config.Method)
		return
	}
	payloadcipher, err := gcm.Encrypt(append([]byte(addr), ciphermethod))
	if err != nil {
		log.Errorf("gcm.Encrypt err:%+v", err)
		return
	}

	handshake := append(headercipher, payloadcipher...)
	_, err = stream.Write(handshake)
	if err != nil {
		log.Errorf("stream.Write err:%+v", errors.WithStack(err))
		if pc, ok := stream.(*easypool.PoolConn); ok {
			log.Infof("mark pool conn stream unusable")
			pc.MarkUnusable()
		}
		return
	}

	csStream, err := cipherstream.New(stream, ss.config.Password, ss.config.Method)
	if err != nil {
		log.Errorf("new cipherstream err:%+v, password:%v, method:%v",
			err, ss.config.Password, ss.config.Method)
		return
	}

	n1, n2, needclose := relay(csStream, localConn)
	log.Infof("send %v bytes to %v, and recive %v bytes", n1, addr, n2)
	if !needclose {
		log.Infof("underline connection is health, so reuse it")
	}

	return
}

func EncodeCipherMethod(m string) byte {
	methodMap := map[string]byte{
		"aes-256-gcm":       1,
		"chacha20-poly1305": 2,
	}
	if b, ok := methodMap[m]; ok {
		return b
	}
	return 0
}
