package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"strconv"
	"time"

	quic "github.com/lucas-clemente/quic-go"
	"github.com/nange/easyss/cipherstream"
	"github.com/nange/easyss/socks"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

func (ss *Easyss) Remote() {
	if ss.config.EnableQuic {
		ss.quicServer()
	} else {
		ss.tcpServer()
	}
}

func (ss *Easyss) quicServer() {
	addr := ":" + strconv.Itoa(ss.config.ServerPort)
	ln, err := quic.ListenAddr(addr, generateTLSConfig(), &quic.Config{IdleTimeout: time.Minute})
	if err != nil {
		log.Fatal(err)
	}
	log.Infof("starting remote quic server at %v ...", addr)

	for {
		sess, err := ln.Accept()
		if err != nil {
			log.Error("accept:", err)
			continue
		}
		log.Infof("a new session(ip) is accepted. remote addr:%v\n", sess.RemoteAddr())

		go func(sess quic.Session) {
			for {
				stream, err := sess.AcceptStream()
				if err != nil {
					log.Warnf("session accept stream err, remote addr:%v, message: %+v\n",
						sess.RemoteAddr(), errors.WithStack(err))
					sess.Close(err)
					return
				}

				go func(stream quic.Stream) {
					defer stream.Close()
					log.Infof("a new stream is accepted. stream id:%v\n", stream.StreamID())

					addr, err := getTargetAddr(stream, ss.config.Password)
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

					csStream, err := cipherstream.New(stream, ss.config.Password, ss.config.Method)
					if err != nil {
						log.Errorf("new cipherstream err:%+v, password:%v, method:%v",
							err, ss.config.Password, ss.config.Method)
						return
					}

					go func() {
						defer stream.Close()
						defer tconn.Close()
						n, err := io.Copy(csStream, tconn)
						log.Infof("reciveve %v bytes from %v, message:%v", n, addr, err)
					}()
					n, err := io.Copy(tconn, csStream)
					log.Infof("send %v bytes to %v, message:%v", n, addr, err)
				}(stream)

			}
		}(sess)
	}
}

func (ss *Easyss) tcpServer() {
	addr := ":" + strconv.Itoa(ss.config.ServerPort)
	ln, err := net.Listen("tcp", addr)
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

		conn.(*net.TCPConn).SetKeepAlive(true)
		conn.(*net.TCPConn).SetKeepAlivePeriod(30 * time.Second)

		go func() {
			defer conn.Close()
			for {
				addr, err := getTargetAddr(conn, ss.config.Password)
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

				csStream, err := cipherstream.New(conn, ss.config.Password, ss.config.Method)
				if err != nil {
					log.Errorf("new cipherstream err:%+v, password:%v, method:%v",
						err, ss.config.Password, ss.config.Method)
					return
				}

				n1, n2, needclose := relay(csStream, tconn, false)
				log.Infof("send %v bytes to %v, and recive %v bytes, needclose:%v", n2, addr, n1, needclose)

				tconn.Close()
				if needclose {
					log.Infof("maybe underline connection have been closed, need close the proxy conn")
					break
				}
				log.Infof("underline connection is health, so reuse it")
			}
		}()
	}
}

func getTargetAddr(stream io.ReadWriter, password string) (addr socks.Addr, err error) {
	gcm, err := cipherstream.NewAes256GCM([]byte(password))
	if err != nil {
		return
	}

	headerbuf := make([]byte, 9+gcm.NonceSize()+gcm.Overhead())
	if _, err = io.ReadFull(stream, headerbuf); err != nil {
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
	if _, err = io.ReadFull(stream, payloadbuf); err != nil {
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

// Setup a bare-bones TLS config for the server
func generateTLSConfig() *tls.Config {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	template := x509.Certificate{SerialNumber: big.NewInt(1)}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		panic(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{tlsCert}}
}
