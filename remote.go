package easyss

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/nange/easyss/v2/cipherstream"
	"github.com/nange/easyss/v2/httptunnel"
	"github.com/nange/easyss/v2/log"
	"github.com/nange/easyss/v2/util"
	"github.com/nange/easyss/v2/util/netpipe"
	"github.com/txthinking/socks5"
)

func (es *EasyServer) Start() {
	if err := es.initTLSConfig(); err != nil {
		log.Error("[REMOTE] init tls config", "err", err)
		os.Exit(1)
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
		log.Info("[REMOTE] using self-signed cert", "cert_path", es.CertPath(), "key_path", es.KeyPath())
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
	tlsConfig.CipherSuites = TLSCipherSuites

	tlsConfig.NextProtos = append([]string{"http/1.1", "h2", "h3"}, tlsConfig.NextProtos...)
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
		ln, err = tls.Listen("tcp", addr, es.tlsConfig.Clone())
	}
	if err != nil {
		log.Error("Listen", "addr", addr, "err", err)
		os.Exit(1)
	}

	es.mu.Lock()
	es.ln = ln
	es.mu.Unlock()

	log.Info("[REMOTE] starting remote socks5 server at", "addr", addr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Error("[REMOTE] accept:", "err", err)
			break
		}
		log.Info("[REMOTE] a new connection(ip) is accepted", "addr", conn.RemoteAddr())

		go es.handleConn(conn, true)
	}
}

func (es *EasyServer) startHTTPTunnelServer() {
	server := httptunnel.NewServer(es.ListenHTTPTunnelAddr(), es.MaxConnWaitTimeout(), es.tlsConfig.Clone())
	es.mu.Lock()
	es.httpTunnelServer = server
	es.mu.Unlock()

	go server.Listen()

	for {
		conn, err := server.Accept()
		if err != nil {
			log.Error("[REMOTE] http tunnel server accept:", "err", err)
			break
		}
		log.Info("[REMOTE] a http tunnel connection is accepted", "remote_addr", conn.RemoteAddr().String())

		go es.handleConn(conn, false)
	}
}

func (es *EasyServer) handleConn(conn net.Conn, tryReuse bool) {
	defer conn.Close()

	for {
		res, err := es.handShakeWithClient(conn)
		if err != nil {
			if errors.Is(err, io.EOF) {
				log.Debug("[REMOTE] got EOF error when handshake with client-server, maybe the connection pool closed the idle conn")
			} else if !errors.Is(err, netpipe.ErrReadDeadline) {
				log.Warn("[REMOTE] handshake with client", "err", err)
			}
			return
		}

		addrStr := string(res.addr)
		if !es.disableValidateAddr {
			if err := validateTargetAddr(addrStr); err != nil {
				log.Warn("[REMOTE] invalid target address, close the connection directly", "err", err)
				return
			}
		}

		log.Info("[REMOTE]", "target", addrStr)

		switch {
		case res.frameHeader.IsTCPProto():
			if err := es.remoteTCPHandle(conn, addrStr, res.method, tryReuse); err != nil {
				log.Warn("[REMOTE] tcp handle", "err", err)
				return
			}
		case res.frameHeader.IsUDPProto():
			if err := es.remoteUDPHandle(conn, addrStr, res.method, res.frameHeader.IsDNSProto(), tryReuse); err != nil {
				log.Warn("[REMOTE] udp handle", "err", err)
				return
			}
		default:
			log.Error("[REMOTE] unsupported proto_type")
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

	log.Debug("[REMOTE] send bytes to, and receive bytes", "send_bytes", n2, "to", addrStr, "receive", n1)

	return err
}

type hsRes struct {
	addr        []byte
	method      string
	frameHeader *cipherstream.Header
}

func (es *EasyServer) handShakeWithClient(conn net.Conn) (hsRes, error) {
	res := hsRes{}
	csStream, err := cipherstream.New(conn, es.Password(), cipherstream.MethodAes256GCM, cipherstream.FrameTypeUnknown)
	if err != nil {
		return res, err
	}
	cs := csStream.(*cipherstream.CipherStream)

	_ = csStream.SetReadDeadline(time.Now().Add(es.MaxConnWaitTimeout()))
	defer func() {
		_ = csStream.SetReadDeadline(time.Time{})
		cs.Release()
	}()

	var frame *cipherstream.Frame
	for {
		frame, err = cs.ReadFrame()
		if err != nil {
			return res, err
		}

		_ = csStream.SetReadDeadline(time.Now().Add(es.MaxConnWaitTimeout()))

		if frame.IsPingFrame() {
			log.Debug("[REMOTE] got ping message",
				"payload", string(frame.RawDataPayload()), "is_need_ack", frame.IsNeedACK())
			if frame.IsNeedACK() {
				if er := cs.WritePing(frame.RawDataPayload(), cipherstream.FlagACK); er != nil {
					return res, er
				}
			}
			continue
		}
		break
	}
	res.frameHeader = frame.Header

	rawData := frame.RawDataPayload()
	length := len(rawData)
	if length <= 1 {
		return res, errors.New("handshake: payload length is invalid")

	}
	res.method = DecodeCipherMethod(rawData[length-1])
	res.addr = rawData[:length-1]

	return res, nil
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
			subs := subDomains(host)
			for _, sub := range subs {
				if _, ok := es.nextProxyDomains[sub]; ok {
					return true
				}
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
		log.Info("[REMOTE] next proxy for", "addr", addr, "network", network)
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
	if util.IsLANIP(host) {
		return fmt.Errorf("target address should not be LAN ip:%s", addr)
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
