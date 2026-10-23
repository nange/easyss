package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/nange/easyss/v3/client/config"
	"github.com/nange/easyss/v3/log"
)

type ForwardServer struct {
	listenAddr  string
	client      *dns.Client
	dnsServers  []string
	disableIPV6 bool
	// system 是系统 DNS 兜底列表的来源，归实例所有以便测试注入。
	system systemServers

	// static 为 nil 时静态名钩子完全关闭，行为与今天完全一致。
	static StaticNames

	mu sync.Mutex
	// pc 由 Shutdown 直接关闭：落在 dns.Server 尚未置位 started 的窗口里时端口也必须释放。
	pc        net.PacketConn
	dnsServer *dns.Server
	// closing 在 mu 下置位，Serve 登记 socket 前检查它，迟到的 Serve 不得把服务器拉起来。
	closing bool
}

// NewForwardServer 构造转发服务器。static 为 nil 表示没有静态名钩子（VPN 未启用
// 或本会话没有本地静态名），此时每个查询都按原有路径转发。
func NewForwardServer(listenAddr string, disableIPV6 bool, static StaticNames) *ForwardServer {
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
		client:      &dns.Client{Timeout: dnsQueryTimeout},
		dnsServers:  servers,
		disableIPV6: disableIPV6,
		system:      defaultSystemDNS,
		static:      static,
	}
}

// Start 自行绑定 socket；需要绑定失败在 Run 返回前暴露的调用方用 Serve 交入 socket。
func (s *ForwardServer) Start() error {
	pc, err := net.ListenPacket("udp", s.listenAddr)
	if err != nil {
		return err
	}
	return s.Serve(pc)
}

// Serve 接管调用方已绑定的 socket；Shutdown 先到时它关掉该 socket 并返回 net.ErrClosed。
func (s *ForwardServer) Serve(pc net.PacketConn) error {
	srv := &dns.Server{
		PacketConn: pc,
		Handler:    dns.HandlerFunc(s.handleDNS),
	}

	s.mu.Lock()
	if s.closing {
		s.mu.Unlock()
		_ = pc.Close()
		return net.ErrClosed
	}
	s.pc = pc
	s.dnsServer = srv
	s.mu.Unlock()

	log.Info("[DNS-FORWARD] starting forward dns server", "addr", pc.LocalAddr().String())

	return srv.ActivateAndServe()
}

// Shutdown 幂等，不依赖 dns.Server 是否已启动：PacketConn 一定会被关闭，端口必然释放。
func (s *ForwardServer) Shutdown() error {
	s.mu.Lock()
	alreadyClosed := s.closing
	s.closing = true
	srv, pc := s.dnsServer, s.pc
	s.mu.Unlock()

	if alreadyClosed {
		return nil
	}

	log.Info("[DNS-FORWARD] shutting down dns server")
	if srv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.ShutdownContext(ctx); err != nil {
			// 含 Shutdown 早于 serve 循环的 "server not started"，其 socket 由 pc.Close 释放。
			log.Warn("[DNS-FORWARD] graceful shutdown incomplete", "err", err)
		}
	}
	if pc != nil {
		_ = pc.Close()
	}

	s.mu.Lock()
	s.pc = nil
	s.mu.Unlock()
	return nil
}

func (s *ForwardServer) handleDNS(w dns.ResponseWriter, r *dns.Msg) {
	if len(r.Question) == 0 {
		return
	}

	q := r.Question[0]

	// 静态名先于任何上游查询就地应答：这些名字（VPN 对端）在上游 DNS 里不存在，
	// 转发出去只会得到 NXDOMAIN。语义与代理侧共用（见 StaticReply）。
	if reply, ok := StaticReply(s.static, r); ok {
		_ = w.WriteMsg(reply)
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

	// 并发查询全部上游并取第一个成功结果，整个查询共享一个超时预算：串行扫描会让一个
	// 挂起的上游吃掉客户端整个读超时。
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
				// 上游可能返回"OPT 在 ANSWER 段"的畸形 EDNS0 应答：不规范化则严格解析器判畸形、
				// 宽松解析器拿不到地址。
				NormalizeEDNS0Answer(r.reply)
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

// 回退上游里必须过滤掉会打回本转发服务器的条目：监听通配地址时"自环"还包括本机所有网卡
// 地址，用它作上游会递归回自身并一直堆积查询直到超时。
func (s *ForwardServer) systemDNSServers() []string {
	servers := s.system.Servers()

	var filtered []string
	for _, srv := range servers {
		if s.disableIPV6 && strings.Contains(srv, "]:") {
			continue
		}
		if isSelfUpstreamAddr(srv, s.listenAddr) {
			continue
		}
		filtered = append(filtered, srv)
	}
	return filtered
}
