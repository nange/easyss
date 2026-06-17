package dns

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/nange/easyss/v3/log"
)

// DirectDNSServers are the public DNS servers used for direct (non-proxied) DNS lookups.
var DirectDNSServers = []string{"223.5.5.53:53", "119.29.29.29:53", "[2400:3200::1]:53", "[2400:3200:baba::1]:53"}

// ProxyDNSServer is the upstream DNS server used when proxying DNS queries through the tunnel.
const ProxyDNSServer = "8.8.8.8:53"

type ForwardServer struct {
	listenAddr string
	client     *dns.Client
	dnsServer  *dns.Server
	mu         sync.Mutex
	running    bool
}

func NewForwardServer(listenAddr string) *ForwardServer {
	return &ForwardServer{
		listenAddr: listenAddr,
		client:     &dns.Client{},
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

	for _, server := range DirectDNSServers {
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
