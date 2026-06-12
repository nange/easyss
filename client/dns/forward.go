package dns

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/coocood/freecache"
	"github.com/miekg/dns"
	"github.com/nange/easyss/v3/log"
)

const (
	defaultDNSCacheSize = 2 * 1024 * 1024
	defaultDNSCacheTTL  = 2 * 60 * 60
)

var directDNSServers = []string{"223.5.5.53:53", "119.29.29.29:53"}

type ForwardServer struct {
	listenAddr string
	cache      *freecache.Cache
	client     *dns.Client
	dnsServer  *dns.Server
	mu         sync.Mutex
	running    bool
}

func NewForwardServer(listenAddr string) *ForwardServer {
	return &ForwardServer{
		listenAddr: listenAddr,
		cache:      freecache.NewCache(defaultDNSCacheSize),
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
	key := q.Name + dns.TypeToString[q.Qtype]

	if cached := s.getFromCache(key); cached != nil {
		cached.SetReply(r)
		_ = w.WriteMsg(cached)
		return
	}

	reply, err := s.forwardQuery(r)
	if err != nil {
		log.Debug("[DNS-FORWARD] forward query failed", "name", q.Name, "err", err)
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeServerFailure)
		_ = w.WriteMsg(m)
		return
	}

	s.setCache(key, reply)
	reply.SetReply(r)
	_ = w.WriteMsg(reply)
}

func (s *ForwardServer) forwardQuery(msg *dns.Msg) (*dns.Msg, error) {
	var lastErr error

	for _, server := range directDNSServers {
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

func (s *ForwardServer) getFromCache(key string) *dns.Msg {
	v, err := s.cache.Get([]byte(key))
	if err != nil || len(v) == 0 {
		return nil
	}
	msg := &dns.Msg{}
	if err := msg.Unpack(v); err != nil {
		return nil
	}
	return msg
}

func (s *ForwardServer) setCache(key string, msg *dns.Msg) {
	if msg == nil {
		return
	}
	v, err := msg.Pack()
	if err != nil {
		return
	}
	_ = s.cache.Set([]byte(key), v, defaultDNSCacheTTL)
}

func (s *ForwardServer) IsRunning() bool {
	return s.running
}
