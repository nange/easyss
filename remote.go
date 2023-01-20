package easyss

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strconv"

	"github.com/caddyserver/certmagic"
	"github.com/nange/easyss/v2/cipherstream"
	"github.com/nange/easyss/v2/util"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

func (es *EasyServer) Start() {
	es.startTCPServer()
}

func (es *EasyServer) tlsConfig() (*tls.Config, error) {
	var tlsConfig *tls.Config
	var err error
	if es.CertPath() != "" && es.KeyPath() != "" {
		log.Infof("[REMOTE] using self-signed cert, cert-path:%s, key-path:%s", es.CertPath(), es.KeyPath())
		var cer tls.Certificate
		if cer, err = tls.LoadX509KeyPair(es.CertPath(), es.KeyPath()); err != nil {
			return nil, err
		}
		tlsConfig = &tls.Config{Certificates: []tls.Certificate{cer}}
	} else {
		tlsConfig, err = certmagic.TLS([]string{es.Server()})
		if err != nil {
			return nil, err
		}
	}

	tlsConfig.NextProtos = append(tlsConfig.NextProtos, []string{"h2", "http/1.1"}...)
	if !es.DisableUTLS() {
		tlsConfig.VerifyConnection = func(cs tls.ConnectionState) error {
			for _, v := range tlsConfig.NextProtos {
				if cs.NegotiatedProtocol == v {
					return nil
				}
			}
			return fmt.Errorf("unsupported ALPN:%s", cs.NegotiatedProtocol)
		}
	}

	return tlsConfig, nil
}

func (es *EasyServer) startTCPServer() {
	addr := ":" + strconv.Itoa(es.ServerPort())
	tlsConfig, err := es.tlsConfig()
	if err != nil {
		log.Fatalf("[REMOTE] get server tls config err:%v", err)
	}

	ln, err := tls.Listen("tcp", addr, tlsConfig)
	if err != nil {
		log.Fatal(err)
	}
	log.Infof("[REMOTE] starting remote socks5 server at %v ...", addr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Error("accept:", err)
			continue
		}
		log.Infof("[REMOTE] a new connection(ip) is accepted. addr:%v", conn.RemoteAddr())

		go func() {
			defer conn.Close()

			for {
				addr, method, protoType, err := es.handShakeWithClient(conn)
				if err != nil {
					if errors.Is(err, io.EOF) {
						log.Debugf("[REMOTE] got EOF error when handshake with client-server, maybe the connection pool closed the idle conn")
					} else {
						log.Warnf("[REMOTE] handshake with client:%+v", err)
					}
					return
				}

				addrStr := string(addr)
				if err := validateTargetAddr(addrStr); err != nil {
					log.Warnf("[REMOTE] validate target address err:%s, close the connection directly", err.Error())
					return
				}

				log.Infof("[REMOTE] target:%v", addrStr)

				switch protoType {
				case "tcp":
					if err := es.remoteTCPHandle(conn, addrStr, method); err != nil {
						log.Errorf("[REMOTE] tcp handle err:%v", err)
						return
					}
				case "udp":
					if err := es.remoteUDPHandle(conn, addrStr, method); err != nil {
						log.Errorf("[REMOTE] udp handle err:%v", err)
						return
					}
				default:
					log.Errorf("[REMOTE] unsupported protoType:%s", protoType)
					return
				}
			}
		}()
	}
}

func (es *EasyServer) remoteTCPHandle(conn net.Conn, addrStr, method string) error {
	tConn, err := net.DialTimeout("tcp", addrStr, es.Timeout())
	if err != nil {
		return fmt.Errorf("net.Dial %v err:%v", addrStr, err)
	}

	csStream, err := cipherstream.New(conn, es.Password(), method, util.FrameTypeData, util.FlagTCP)
	if err != nil {
		return fmt.Errorf("new cipherstream err:%+v, password:%v, method:%v",
			err, es.Password(), method)
	}

	n1, n2 := relay(csStream, tConn, es.Timeout())
	csStream.(*cipherstream.CipherStream).Release()

	log.Debugf("[REMOTE] send %v bytes to %v, and recive %v bytes", n2, addrStr, n1)

	_ = tConn.Close()

	return nil
}

func (es *EasyServer) handShakeWithClient(conn net.Conn) (addr []byte, method string, protoType string, err error) {
	csStream, err := cipherstream.New(conn, es.Password(), cipherstream.MethodAes256GCM, util.FrameTypeUnknown)
	if err != nil {
		return nil, "", "", err
	}
	cs := csStream.(*cipherstream.CipherStream)
	defer cs.Release()

	var header, payload []byte
	for {
		header, payload, err = cs.ReadHeaderAndPayload()
		if err != nil {
			return nil, "", "", err
		}

		if util.IsPingFrame(header) {
			log.Infof("[REMOTE] got ping message, payload:%s", string(payload))
			if util.IsNeedACK(header) {
				if er := cs.WritePing(payload, util.FlagACK); er != nil {
					return nil, "", "", er
				}
			}
			continue
		}
		break
	}
	if util.IsTCPProto(header) {
		protoType = "tcp"
	} else if util.IsUDPProto(header) {
		protoType = "udp"
	}

	length := len(payload)
	if length <= 1 {
		err = errors.New("handshake: payload length is invalid")
		return
	}
	method = DecodeCipherMethod(payload[length-1])

	return payload[:length-1], method, protoType, nil
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
		1: cipherstream.MethodAes256GCM,
		2: cipherstream.MethodChaCha20Poly1305,
	}
	if m, ok := methodMap[b]; ok {
		return m
	}
	return ""
}
