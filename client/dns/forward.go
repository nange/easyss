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

	mu sync.Mutex
	// pc 是本服务器自己绑定的 UDP socket：Shutdown 直接关闭它，因此即使
	// Shutdown 落在 dns.Server 尚未置位 started 的窗口里，端口也一定会被释放
	// （miekg/dns 的 ShutdownContext 对未启动的服务器只返回错误，什么都不做）。
	pc net.PacketConn
	// dnsServer 与 pc 一同登记，供 Shutdown 优雅关闭（等待在飞查询）。
	dnsServer *dns.Server
	// closing 由 Shutdown 在 mu 下置位；Start 在登记 socket 之前检查它，
	// 使"先 Shutdown 再 Start"不会把服务器重新拉起来。
	closing bool
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
		client:      &dns.Client{Timeout: dnsQueryTimeout},
		dnsServers:  servers,
		disableIPV6: disableIPV6,
	}
}

// Start 绑定监听 socket 并开始服务。socket 在向内部状态登记之前就已绑定，
// 因此无论 Shutdown 落在哪个时刻，端口都会被释放（见 pc 字段）。
func (s *ForwardServer) Start() error {
	pc, err := net.ListenPacket("udp", s.listenAddr)
	if err != nil {
		return err
	}

	srv := &dns.Server{
		PacketConn: pc,
		Handler:    dns.HandlerFunc(s.handleDNS),
	}

	s.mu.Lock()
	if s.closing {
		// Shutdown 已发生：绝不把这个迟到的 socket 留在服务状态里，
		// 否则它就再也没人关了。
		s.mu.Unlock()
		_ = pc.Close()
		return net.ErrClosed
	}
	s.pc = pc
	s.dnsServer = srv
	s.mu.Unlock()

	log.Info("[DNS-FORWARD] starting forward dns server", "addr", s.listenAddr)

	return srv.ActivateAndServe()
}

// Shutdown 关闭监听 socket 并等待在飞查询结束。它是幂等的，且不依赖 dns.Server
// 是否已进入 started 状态：自己持有的 PacketConn 一定会被关闭，端口也就一定会
// 释放（dns.Server.ShutdownContext 在未启动时只返回 "server not started"，不会
// 关闭任何东西）。
//
// 它不关闭借用的依赖：client/dnsServers 由本类型构造期持有，无需释放。
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
			// "server not started"（Shutdown 早于 serve 循环）与超时都在这里：
			// 前者的端口由下面的 pc.Close 释放，后者说明在飞查询没能在预算内
			// 结束，socket 同样会被关掉。
			log.Warn("[DNS-FORWARD] graceful shutdown incomplete", "err", err)
		}
	}
	if pc != nil {
		_ = pc.Close()
	}
	return nil
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

	// 并发查询每个上游服务器并取第一个成功结果。串行扫描会让一个挂起的
	// 上游占用整个客户端超时时间；整个查询共享同一个超时预算。
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
				// 上游可能返回"OPT 在 ANSWER 段"的畸形 EDNS0 应答（见
				// normalizeEDNS0Answer）；转交给客户端前先规范化，否则客户端
				// 的严格解析器会判为畸形报文、宽松解析器则拿不到任何地址。
				normalizeEDNS0Answer(r.reply)
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

// systemDNSServers 返回系统 DNS 服务器作为回退上游，禁用 IPv6 时过滤掉
// IPv6 服务器。会打回本转发服务器自身的条目总是被丢弃：转发服务器监听通配
// 地址（见 runner.forwardDNSListenAddr），因此"自环地址"不只是 127.0.0.1，
// 还包括本机所有网卡地址——系统解析器可能被配置为本机地址（路由器上
// /etc/resolv.conf 指向 127.0.0.1 是 dnsmasq 的惯例），把它用作回退上游会
// 递归回自身（查询 -> 回退 -> 本机:53 -> 同一查询），堆积 goroutine 和 UDP
// socket，直到单次查询的超时解开这条链。判定见 isSelfUpstreamAddr。
func (s *ForwardServer) systemDNSServers() []string {
	servers := systemDNSServersFunc()

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
