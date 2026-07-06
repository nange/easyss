package dns

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/nange/easyss/v3/client/config"
	"github.com/nange/easyss/v3/log"
)

type ForwardServer struct {
	listenAddr string
	client     *dns.Client
	dnsServers []string
	dnsServer  *dns.Server
	mu         sync.Mutex
	running    bool
}

func NewForwardServer(listenAddr string, disableIPV6 bool) *ForwardServer {
	servers := config.DirectDNSServers
	if disableIPV6 {
		var filtered []string
		for _, s := range servers {
			if !strings.Contains(s, "]:") {
				filtered = append(filtered, s)
			}
		}
		if len(filtered) > 0 {
			servers = filtered
		}
	}
	return &ForwardServer{
		listenAddr: listenAddr,
		client:     &dns.Client{},
		dnsServers: servers,
	}
}

func (s *ForwardServer) Start() error {
	s.mu.Lock()
	s.dnsServer = &dns.Server{
		Addr:    s.listenAddr,
		Net:     "udp",
		Handler: dns.HandlerFunc(s.handleDNS),
	}
	s.running = true
	s.mu.Unlock()

	log.Info("[DNS-FORWARD] starting forward dns server", "addr", s.listenAddr)

	return s.dnsServer.ListenAndServe()
}

func (s *ForwardServer) Shutdown() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.dnsServer == nil {
		return nil
	}

	log.Info("[DNS-FORWARD] shutting down dns server")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return s.dnsServer.ShutdownContext(ctx)
}

func (s *ForwardServer) handleDNS(w dns.ResponseWriter, r *dns.Msg) {
	if len(r.Question) == 0 {
		return
	}

	q := r.Question[0]

	reply, err := s.forwardQuery(r)
	if err != nil {
		log.Debug("[DNS-FORWARD] forward query failed", "name", q.Name, "err", err)
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeServerFailure)
		_ = w.WriteMsg(m)
		return
	}

	reply.SetReply(r)
	_ = w.WriteMsg(reply)
}

func (s *ForwardServer) forwardQuery(msg *dns.Msg) (*dns.Msg, error) {
	var lastErr error

	for _, server := range s.dnsServers {
		reply, _, err := s.client.Exchange(msg, server)
		if err != nil {
			lastErr = err
			continue
		}
		if reply != nil && reply.Rcode == dns.RcodeSuccess {
			return reply, nil
		}
		lastErr = fmt.Errorf("dns: server returned %s", dns.RcodeToString[reply.Rcode])
	}

	return nil, lastErr
}

func (s *ForwardServer) IsRunning() bool {
	return s.running
}
