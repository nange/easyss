package easyss

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync/atomic"

	"github.com/caddyserver/certmagic"
	"github.com/nange/easyss/cipherstream"
	"github.com/nange/easyss/util"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

var remoteBytespool = util.NewBytes(512)

func (ss *Easyss) Remote() {
	ss.tcpServer()
}

func (ss *Easyss) tcpServer() {
	addr := ":" + strconv.Itoa(ss.config.ServerPort)
	tlsConfig, err := certmagic.TLS([]string{ss.config.Server})
	if err != nil {
		log.Fatal(err)
	}
	ln, err := tls.Listen("tcp", addr, tlsConfig)
	if err != nil {
		log.Fatal(err)
	}
	log.Infof("starting remote socks5 server at %v ...", addr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Error("accept:", err)
			continue
		}
		log.Infof("a new connection(ip) is accepted. remote addr:%v", conn.RemoteAddr())

		go func() {
			defer conn.Close()
			for {
				addr, ciphermethod, err := handShake(conn, ss.config.Password)
				if err != nil {
					if errors.Is(err, io.EOF) {
						log.Debugf("got EOF error when handShake with client-server, maybe the connection pool closed the idle conn")
					} else {
						log.Warnf("get target addr err:%+v", err)
					}
					return
				}
				addrStr := string(addr)
				if addrStr == "" || ciphermethod == "" {
					log.Errorf("after handshake with client, but get empty addr:%v or ciphermethod:%v",
						addrStr, ciphermethod)
					return
				}
				if addrStr == "localhost" || addrStr == "127.0.0.1" {
					log.Warnf("target addr should not be localhost, close the connection directly")
					return
				}
				if util.IsPrivateIP(addrStr) {
					log.Warnf("target addr should not be private ip, close the connection directly")
					return
				}

				log.Infof("target proxy addr is:%v", addrStr)

				tconn, err := net.Dial("tcp", addrStr)
				if err != nil {
					log.Errorf("net.Dial %v err:%v", addrStr, err)
					return
				}

				csStream, err := cipherstream.New(conn, ss.config.Password, ciphermethod)
				if err != nil {
					log.Errorf("new cipherstream err:%+v, password:%v, method:%v",
						err, ss.config.Password, ss.config.Method)
					return
				}

				n1, n2, needClose := relay(csStream, tconn)
				csStream.(*cipherstream.CipherStream).Release()

				log.Debugf("send %v bytes to %v, and recive %v bytes, needclose:%v", n2, addrStr, n1, needClose)

				atomic.AddInt64(&ss.stat.BytesSend, n2)
				atomic.AddInt64(&ss.stat.BytesRecive, n1)

				tconn.Close()
				if needClose {
					log.Debugf("maybe underline connection have been closed, need close the proxy conn")
					break
				}
				log.Debugf("underline connection is health, so reuse it")
			}
		}()
	}
}

func handShake(stream io.ReadWriter, password string) (addr []byte, ciphermethod string, err error) {
	gcm, err := cipherstream.NewAes256GCM([]byte(password))
	if err != nil {
		return
	}

	headerbuf := remoteBytespool.Get(9 + gcm.NonceSize() + gcm.Overhead())
	defer remoteBytespool.Put(headerbuf)

	if _, err = io.ReadFull(stream, headerbuf); err != nil {
		err = errors.WithStack(err)
		return
	}

	headerplain, err := gcm.Decrypt(headerbuf)
	if err != nil {
		log.Errorf("gcm.Decrypt decrypt headerbuf:%v, err:%+v", headerbuf, err)
		return
	}

	payloadlen := int(headerplain[0])<<16 | int(headerplain[1])<<8 | int(headerplain[2])
	if headerplain[3] != 0x0 {
		err = errors.New(fmt.Sprintf("http2 data frame type:%v is invalid, should be 0x0", headerplain[3]))
		return
	}

	payloadbuf := remoteBytespool.Get(payloadlen + gcm.NonceSize() + gcm.Overhead())
	defer remoteBytespool.Put(payloadbuf)

	if _, err = io.ReadFull(stream, payloadbuf); err != nil {
		err = errors.WithStack(err)
		log.Warnf("io.ReadFull read payloadbuf err:%+v, len:%v", err, len(payloadbuf))
		return
	}

	payloadplain, err := gcm.Decrypt(payloadbuf)
	if err != nil {
		log.Errorf("gcm.Decrypt decrypt payloadbuf:%v, err:%+v", payloadbuf, err)
		return
	}
	length := len(payloadplain)
	if length <= 1 {
		err = errors.New("handshake: payload length is invalid")
		return
	}
	ciphermethod = DecodeCipherMethod(payloadplain[length-1])

	if headerplain[4] == 0x8 { // has padding field
		paddingbuf := remoteBytespool.Get(cipherstream.PaddingSize + gcm.NonceSize() + gcm.Overhead())
		defer remoteBytespool.Put(paddingbuf)

		if _, err = io.ReadFull(stream, paddingbuf); err != nil {
			err = errors.WithStack(err)
			log.Warnf("io.ReadFull read paddingbuf err:%+v, len:%v", err, len(paddingbuf))
			return
		}
		_, err = gcm.Decrypt(paddingbuf)
		if err != nil {
			log.Errorf("gcm.Decrypt decrypt paddingbuf:%v, err:%+v", paddingbuf, err)
			return
		}
	}

	return payloadplain[:length-1], ciphermethod, nil
}

func DecodeCipherMethod(b byte) string {
	methodMap := map[byte]string{
		1: "aes-256-gcm",
		2: "chacha20-poly1305",
	}
	if m, ok := methodMap[b]; ok {
		return m
	}
	return ""
}
