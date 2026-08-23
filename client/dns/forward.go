package dns

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/nange/easyss/v3/client/config"
	"github.com/nange/easyss/v3/log"
)

type ForwardServer struct {
	listenAddr  string
	client      *dns.Client
	dnsServers  []string
	dnsServer   *dns.Server
	disableIPV6 bool
	mu          sync.Mutex
	running     atomic.Bool
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
		listenAddr:  listenAddr,
		client:      &dns.Client{Timeout: 5 * time.Second},
		dnsServers:  servers,
		disableIPV6: disableIPV6,
	}
}

func (s *ForwardServer) Start() error {
	s.mu.Lock()
	s.dnsServer = &dns.Server{
		Addr:    s.listenAddr,
		Net:     "udp",
		Handler: dns.HandlerFunc(s.handleDNS),
	}
	s.running.Store(true)
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
	err := s.dnsServer.ShutdownContext(ctx)
	s.running.Store(false)
	return err
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
	try := func(servers []string) (*dns.Msg, error) {
		return s.exchangeWithServers(servers, msg)
	}
	return QueryWithBuiltinFirst(s.dnsServers, s.systemDNSServers(), try)
}

func (s *ForwardServer) exchangeWithServers(servers []string, msg *dns.Msg) (*dns.Msg, error) {
	if len(servers) == 0 {
		return nil, errors.New("no dns server available")
	}

	// Query every upstream concurrently and take the first success. A
	// serial scan lets one hung upstream stall the query for the full
	// client timeout; the whole query shares a single timeout budget.
	ctx, cancel := context.WithTimeout(context.Background(), s.client.Timeout)
	defer cancel()

	type result struct {
		reply *dns.Msg
		err   error
	}
	ch := make(chan result, len(servers))
	for _, server := range servers {
		go func(server string) {
			reply, _, err := s.client.Exchange(msg, server)
			ch <- result{reply: reply, err: err}
		}(server)
	}

	var lastErr error
	for range servers {
		select {
		case r := <-ch:
			if r.err == nil && r.reply != nil && r.reply.Rcode == dns.RcodeSuccess {
				return r.reply, nil
			}
			if r.err != nil {
				lastErr = r.err
			} else if r.reply == nil {
				lastErr = errors.New("dns: empty reply")
			} else {
				lastErr = fmt.Errorf("dns: server returned %s", dns.RcodeToString[r.reply.Rcode])
			}
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	if lastErr == nil {
		lastErr = errors.New("no dns server available")
	}
	return nil, lastErr
}

// systemDNSServers returns the system dns servers as fallback upstreams,
// filtering out ipv6 ones when ipv6 is disabled.
func (s *ForwardServer) systemDNSServers() []string {
	servers := systemDNSServersFunc()
	if !s.disableIPV6 {
		return servers
	}
	var filtered []string
	for _, srv := range servers {
		if !strings.Contains(srv, "]:") {
			filtered = append(filtered, srv)
		}
	}
	return filtered
}

func (s *ForwardServer) IsRunning() bool {
	return s.running.Load()
}
