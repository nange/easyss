package easyss

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/caddyserver/certmagic"
	"github.com/nange/easyss/v2/cipherstream"
	httptunnel "github.com/nange/easyss/v2/httptunnel"
	"github.com/nange/easyss/v2/util"
	log "github.com/sirupsen/logrus"
	"github.com/txthinking/socks5"
)

func (es *EasyServer) Start() {
	if err := es.initTLSConfig(); err != nil {
		log.Fatalf("[REMOTE] init tls config:%v", err)
	}
	if es.EnabledHTTPInbound() {
		go es.startHTTPTunnelServer()
	}
	es.startTCPServer()
}

func (es *EasyServer) initTLSConfig() error {
	if es.DisableTLS() {
		return nil
	}

	var tlsConfig *tls.Config
	var err error
	if es.CertPath() != "" && es.KeyPath() != "" {
		log.Infof("[REMOTE] using self-signed cert, cert-path:%s, key-path:%s", es.CertPath(), es.KeyPath())
		var cer tls.Certificate
		if cer, err = tls.LoadX509KeyPair(es.CertPath(), es.KeyPath()); err != nil {
			return err
		}
		tlsConfig = &tls.Config{Certificates: []tls.Certificate{cer}}
	} else {
		tlsConfig, err = certmagic.TLS([]string{es.Server()})
		if err != nil {
			return err
		}
	}

	tlsConfig.NextProtos = append([]string{"http/1.1", "h2"}, tlsConfig.NextProtos...)
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
	es.tlsConfig = tlsConfig

	return nil
}

func (es *EasyServer) startTCPServer() {
	var ln net.Listener
	var err error

	addr := es.ListenAddr()
	if es.DisableTLS() {
		ln, err = net.Listen("tcp", addr)
	} else {
		ln, err = tls.Listen("tcp", addr, es.tlsConfig)
	}
	if err != nil {
		log.Fatalf("Listen %v: %v", addr, err)
	}

	es.mu.Lock()
	es.ln = ln
	es.mu.Unlock()

	log.Infof("[REMOTE] starting remote socks5 server at %v ...", addr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Error("[REMOTE] accept:", err)
			break
		}
		log.Infof("[REMOTE] a new connection(ip) is accepted. addr:%v", conn.RemoteAddr())

		go es.handleConn(conn, true)
	}
}

func (es *EasyServer) startHTTPTunnelServer() {
	server := httptunnel.NewServer(es.ListenHTTPTunnelAddr(), es.Timeout(), es.tlsConfig)
	es.mu.Lock()
	es.httpTunnelServer = server
	es.mu.Unlock()

	go server.Listen()

	for {
		conn, err := server.Accept()
		if err != nil {
			log.Error("[REMOTE] http tunnel server accept:", err)
			break
		}
		log.Infof("[REMOTE] a http tunnel connection is accepted")

		go es.handleConn(conn, false)
	}
}

func (es *EasyServer) handleConn(conn net.Conn, tryReuse bool) {
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
		if !es.disableValidateAddr {
			if err := validateTargetAddr(addrStr); err != nil {
				log.Warnf("[REMOTE] validate target address err:%s, close the connection directly", err.Error())
				return
			}
		}

		log.Infof("[REMOTE] target:%v", addrStr)

		switch protoType {
		case "tcp":
			if err := es.remoteTCPHandle(conn, addrStr, method, tryReuse); err != nil {
				log.Infof("[REMOTE] tcp handle: %v", err)
				return
			}
		case "udp":
			if err := es.remoteUDPHandle(conn, addrStr, method, tryReuse); err != nil {
				log.Infof("[REMOTE] udp handle: %v", err)
				return
			}
		default:
			log.Errorf("[REMOTE] unsupported protoType:%s", protoType)
			return
		}
		if !tryReuse {
			return
		}
	}
}

func (es *EasyServer) remoteTCPHandle(conn net.Conn, addrStr, method string, tryReuse bool) error {
	tConn, err := es.targetConn("tcp", addrStr)
	if err != nil {
		return fmt.Errorf("net.Dial %v err:%v", addrStr, err)
	}
	defer tConn.Close()

	csStream, err := cipherstream.New(conn, es.Password(), method, cipherstream.FrameTypeData, cipherstream.FlagTCP)
	if err != nil {
		return fmt.Errorf("new cipherstream err:%v, method:%v", err, method)
	}

	n1, n2, err := relay(csStream, tConn, es.Timeout(), tryReuse)
	csStream.(*cipherstream.CipherStream).Release()

	log.Debugf("[REMOTE] send %v bytes to %v, and recive %v bytes", n2, addrStr, n1)

	return err
}

func (es *EasyServer) handShakeWithClient(conn net.Conn) (addr []byte, method string, protoType string, err error) {
	csStream, err := cipherstream.New(conn, es.Password(), cipherstream.MethodAes256GCM, cipherstream.FrameTypeUnknown)
	if err != nil {
		return nil, "", "", err
	}
	cs := csStream.(*cipherstream.CipherStream)
	defer cs.Release()

	var frame *cipherstream.Frame
	for {
		frame, err = cs.ReadFrame()
		if err != nil {
			return nil, "", "", err
		}

		if frame.IsPingFrame() {
			log.Debugf("[REMOTE] got ping message, payload:%s", string(frame.RawDataPayload()))
			if frame.IsNeedACK() {
				if er := cs.WritePing(frame.RawDataPayload(), cipherstream.FlagACK); er != nil {
					return nil, "", "", er
				}
			}
			continue
		}
		break
	}
	if frame.IsTCPProto() {
		protoType = "tcp"
	} else if frame.IsUDPProto() {
		protoType = "udp"
	}

	rawData := frame.RawDataPayload()
	length := len(rawData)
	if length <= 1 {
		err = errors.New("handshake: payload length is invalid")
		return
	}
	method = DecodeCipherMethod(rawData[length-1])

	return rawData[:length-1], method, protoType, nil
}

func (es *EasyServer) targetConn(network, addr string) (net.Conn, error) {
	var tConn net.Conn
	var err error

	nextProxy := func(host string) bool {
		if network == "udp" && !es.EnableNextProxyUDP() {
			return false
		}
		if es.EnableNextProxyALLHost() {
			return true
		}
		if util.IsIP(host) {
			if _, ok := es.nextProxyIPs[host]; ok {
				return true
			}
			for _, v := range es.nextProxyCIDRIPs {
				if v.Contains(net.ParseIP(host)) {
					return true
				}
			}
		} else {
			if _, ok := es.nextProxyDomains[host]; ok {
				return true
			}
			domain := domainRoot(host)
			if _, ok := es.nextProxyDomains[domain]; ok {
				return true
			}
		}
		return false
	}

	if u := es.NextProxyURL(); u != nil {
		host, _, _ := net.SplitHostPort(addr)
		switch u.Scheme {
		case "socks5":
			var username, password string
			if u.User != nil {
				username = u.User.Username()
				password, _ = u.User.Password()
			}
			if nextProxy(host) {
				cli, _ := socks5.NewClient(u.Host, username, password, 0, 0)
				tConn, err = cli.Dial(network, addr)
			}
		default:
			err = fmt.Errorf("unsupported scheme:%s of next proxy url", u.Scheme)
		}
	}
	if err != nil {
		return nil, err
	}
	if tConn != nil {
		log.Infof("[REMOTE] next proxy for %s, network:%s", addr, network)
	}

	if tConn == nil {
		tConn, err = net.DialTimeout(network, addr, es.Timeout())
	}

	return tConn, err
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
