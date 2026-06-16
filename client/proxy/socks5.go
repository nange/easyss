package proxy

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/nange/easyss/v3/client/router"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/protocol"
	"github.com/txthinking/socks5"
)

type Socks5Server struct {
	srv *socks5.Server

	handler           *StreamHandler
	router            *router.Router
	method            protocol.Method
	disableQUIC       bool
	directDialContext func(context.Context, string, string) (net.Conn, error)
	dialTimeout       time.Duration

	udpMu          sync.RWMutex
	udpExch        map[string]*UDPExchange
	directUDP      map[string]net.Conn
	quit           chan struct{}
	udpIdleTimeout time.Duration
}

func NewSocks5Server(listenAddr, username, password string, handler *StreamHandler, rt *router.Router, method protocol.Method, disableQUIC bool, udpIdleTimeout time.Duration, directDialContext func(context.Context, string, string) (net.Conn, error)) (*Socks5Server, error) {
	if udpIdleTimeout <= 0 {
		udpIdleTimeout = 30 * time.Second
	}
	if directDialContext == nil {
		directDialContext = defaultDirectDialContext
	}
	s := &Socks5Server{
		handler:           handler,
		router:            rt,
		method:            method,
		disableQUIC:       disableQUIC,
		directDialContext: directDialContext,
		dialTimeout:       udpIdleTimeout,
		udpExch:           make(map[string]*UDPExchange),
		directUDP:         make(map[string]net.Conn),
		quit:              make(chan struct{}),
		udpIdleTimeout:    udpIdleTimeout,
	}
	srv, err := socks5.NewClassicServer(listenAddr, "127.0.0.1", username, password, 0, 0)
	if err != nil {
		return nil, err
	}
	s.srv = srv
	return s, nil
}

func defaultDirectDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	dialer := &net.Dialer{}
	return dialer.DialContext(ctx, network, addr)
}

func (s *Socks5Server) Start() error {
	go s.cleanupLoop()
	return s.srv.ListenAndServe(s)
}

func (s *Socks5Server) Close() error {
	close(s.quit)
	s.udpMu.Lock()
	defer s.udpMu.Unlock()
	for key, ue := range s.udpExch {
		ue.Close() //nolint:errcheck
		delete(s.udpExch, key)
	}
	for key, conn := range s.directUDP {
		conn.Close() //nolint:errcheck
		delete(s.directUDP, key)
	}
	if s.srv != nil {
		return s.srv.Shutdown()
	}
	return nil
}

func (s *Socks5Server) TCPHandle(srv *socks5.Server, c *net.TCPConn, r *socks5.Request) error {
	if r.Cmd == socks5.CmdUDP {
		caddr, err := r.UDP(c, srv.ServerAddr)
		if err != nil {
			log.Error("[SOCKS5] udp associate failed", "client", c.RemoteAddr().String(), "err", err)
			return err
		}
		log.Debug("[SOCKS5] udp associate", "client", c.RemoteAddr().String(), "udp", caddr.String())
		ch := make(chan byte)
		srv.AssociatedUDP.Set(caddr.String(), ch, -1)
		defer srv.AssociatedUDP.Delete(caddr.String())
		io.Copy(io.Discard, c) //nolint:errcheck
		log.Debug("[SOCKS5] udp associate tcp closed", "udp", caddr.String())
		return nil
	}

	if r.Cmd != socks5.CmdConnect {
		return s.replyError(c, r, socks5.RepCommandNotSupported)
	}

	target := r.Address()
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		log.Error("[SOCKS5] parse target", "target", target, "err", err)
		return s.replyError(c, r, socks5.RepServerFailure)
	}

	local := c.RemoteAddr().String()
	rule := s.router.MatchHostRule(host)
	switch rule {
	case router.HostRuleBlock:
		log.Info("[TCP_BLOCK] blocked", "host", host, "target", target, "local", local)
		return s.replyError(c, r, socks5.RepNotAllowed)
	case router.HostRuleDirect:
		log.Info("[TCP_DIRECT]", "target", target, "local", local)
		rc, err := s.directTCPConnect(c, r, target)
		if err != nil {
			log.Error("[TCP_DIRECT] connect", "target", target, "err", err)
			return err
		}
		defer rc.Close() //nolint:errcheck
		relayTCP(rc, c)
		log.Debug("[TCP_DIRECT] relay finished", "target", target)
		return nil
	case router.HostRuleProxy:
		log.Info("[TCP_PROXY]", "target", target, "local", local)
		a, bindAddr, bindPort, err := socks5.ParseAddress(c.LocalAddr().String())
		if err != nil {
			log.Error("[TCP_PROXY] parse local addr", "err", err)
			return s.replyError(c, r, socks5.RepServerFailure)
		}
		if a == socks5.ATYPDomain {
			bindAddr = bindAddr[1:]
		}
		p := socks5.NewReply(socks5.RepSuccess, a, bindAddr, bindPort)
		if _, err := p.WriteTo(c); err != nil {
			log.Error("[TCP_PROXY] reply", "err", err)
			return err
		}
		err = s.handler.OpenTCPStream(context.Background(), target, s.method, c)
		if err != nil {
			if errors.Is(err, ErrStreamIdleTimeout) {
				log.Debug("[TCP_PROXY] idle closed", "target", target, "err", err)
				return nil
			}
			log.Error("[TCP_PROXY] stream", "target", target, "err", err)
		} else {
			log.Debug("[TCP_PROXY] stream finished", "target", target)
		}
		return err
	}

	return nil
}

func (s *Socks5Server) directTCPConnect(c net.Conn, r *socks5.Request, target string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), s.dialTimeout)
	defer cancel()

	rc, err := s.directDialContext(ctx, "tcp", target)
	if err != nil {
		_ = s.replyError(c, r, socks5.RepHostUnreachable)
		return nil, err
	}

	a, bindAddr, bindPort, err := socks5.ParseAddress(rc.LocalAddr().String())
	if err != nil {
		rc.Close() //nolint:errcheck
		_ = s.replyError(c, r, socks5.RepHostUnreachable)
		return nil, err
	}
	if a == socks5.ATYPDomain {
		bindAddr = bindAddr[1:]
	}
	p := socks5.NewReply(socks5.RepSuccess, a, bindAddr, bindPort)
	if _, err := p.WriteTo(c); err != nil {
		rc.Close() //nolint:errcheck
		return nil, err
	}

	return rc, nil
}

func (s *Socks5Server) UDPHandle(srv *socks5.Server, addr *net.UDPAddr, d *socks5.Datagram) error {
	return s.handleUDP(srv, addr, d)
}

func (s *Socks5Server) replyError(c net.Conn, r *socks5.Request, rep byte) error {
	var p *socks5.Reply
	if r.Atyp == socks5.ATYPIPv4 || r.Atyp == socks5.ATYPDomain {
		p = socks5.NewReply(rep, socks5.ATYPIPv4, []byte{0, 0, 0, 0}, []byte{0, 0})
	} else {
		p = socks5.NewReply(rep, socks5.ATYPIPv6, []byte(net.IPv6zero), []byte{0, 0})
	}
	_, err := p.WriteTo(c)
	return err
}

func relayTCP(dst, src net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(src, dst)
	}()
	wg.Wait()
}

func (s *Socks5Server) cleanupLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.udpMu.Lock()
			for key, ue := range s.udpExch {
				if time.Since(ue.LastSeen()) > s.udpIdleTimeout {
					log.Debug("[UDP_PROXY] idle cleanup", "key", key)
					ue.Close() //nolint:errcheck
					delete(s.udpExch, key)
				}
			}
			s.udpMu.Unlock()
		case <-s.quit:
			return
		}
	}
}
