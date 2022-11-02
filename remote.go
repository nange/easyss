package easyss

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strconv"

	"github.com/caddyserver/certmagic"
	"github.com/nange/easyss/cipherstream"
	"github.com/nange/easyss/util"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

var remoteBytes = util.NewBytes(512)

func (ss *Easyss) Remote() {
	ss.tcpServer()
}

func (ss *Easyss) tcpServer() {
	addr := ":" + strconv.Itoa(ss.ServerPort())
	tlsConfig, err := certmagic.TLS([]string{ss.Server()})
	if err != nil {
		log.Fatal(err)
	}
	tlsConfig.NextProtos = []string{"h2", "http/1.1"}
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
				addr, method, protoType, err := ss.handShakeWithClient(conn)
				if err != nil {
					if errors.Is(err, io.EOF) {
						log.Debugf("got EOF error when handShake with client-server, maybe the connection pool closed the idle conn")
					} else {
						log.Warnf("get target addr err:%+v", err)
					}
					return
				}

				addrStr := string(addr)
				if err := validateTargetAddr(addrStr); err != nil {
					log.Warnf("validate target address err:%s, close the connection directly", err.Error())
					return
				}

				log.Infof("target proxy addr is:%v", addrStr)

				switch protoType {
				case "tcp":
					needClose, err := ss.remoteTCPHandle(conn, addrStr, method)
					if err != nil {
						log.Errorf("remote tcp handle err:%v", err)
						return
					}
					if needClose {
						log.Debugf("maybe underlying connection has been closed, need close the proxy conn")
						return
					}
					log.Debugf("underlying connection is health, so reuse it")
				case "udp":
					needClose, err := ss.remoteUDPHandle(conn, addrStr, method)
					if err != nil {
						log.Errorf("remote udp handle err:%v", err)
						return
					}
					if needClose {
						log.Infof("maybe underlying connection has been closed, need close the proxy conn")
						return
					}
					log.Infof("underlying connection is health, so reuse it")
				default:
					log.Errorf("unsupported protoType:%s", protoType)
					return
				}
			}
		}()
	}
}

func (ss *Easyss) remoteTCPHandle(conn net.Conn, addrStr, method string) (needClose bool, err error) {
	tConn, err := net.DialTimeout("tcp", addrStr, ss.Timeout())
	if err != nil {
		return false, fmt.Errorf("net.Dial %v err:%v", addrStr, err)
	}

	csStream, err := cipherstream.New(conn, ss.Password(), method, "tcp")
	if err != nil {
		return false, fmt.Errorf("new cipherstream err:%+v, password:%v, method:%v",
			err, ss.Password(), ss.Method())
	}

	n1, n2, needClose := ss.relay(csStream, tConn)
	csStream.(*cipherstream.CipherStream).Release()

	log.Debugf("send %v bytes to %v, and recive %v bytes, needclose:%v", n2, addrStr, n1, needClose)

	ss.stat.BytesSend.Add(n2)
	ss.stat.BytesRecive.Add(n1)

	tConn.Close()

	return needClose, nil
}

func (ss *Easyss) handShakeWithClient(stream io.ReadWriter) (addr []byte, method, protoType string, err error) {
	gcm, err := cipherstream.NewAes256GCM([]byte(ss.Password()))
	if err != nil {
		return
	}

	headerbuf := remoteBytes.Get(9 + gcm.NonceSize() + gcm.Overhead())
	defer remoteBytes.Put(headerbuf)

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
	switch headerplain[3] {
	case 0x0:
		protoType = "tcp"
	case 0x1:
		protoType = "udp"
	default:
		err = errors.New(fmt.Sprintf("http2 data frame type:%v is invalid, should be 0x0 or 0x1", headerplain[3]))
		return
	}

	payloadbuf := remoteBytes.Get(payloadlen + gcm.NonceSize() + gcm.Overhead())
	defer remoteBytes.Put(payloadbuf)

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
	method = DecodeCipherMethod(payloadplain[length-1])

	if headerplain[4] == 0x8 { // has padding field
		paddingbuf := remoteBytes.Get(cipherstream.PaddingSize + gcm.NonceSize() + gcm.Overhead())
		defer remoteBytes.Put(paddingbuf)

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

	return payloadplain[:length-1], method, protoType, nil
}

func validateTargetAddr(addr string) error {
	if addr == "" {
		return fmt.Errorf("target address should not be empty")
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	if util.IsLoopbackIP(host) || util.IsPrivateIP(host) {
		return fmt.Errorf("target address should not be loop-back ip or private ip:%s", addr)
	}

	return nil
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
