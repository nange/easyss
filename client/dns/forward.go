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

	mu sync.Mutex
	// pc 由 Shutdown 直接关闭：落在 dns.Server 尚未置位 started 的窗口里时端口也必须释放。
	pc        net.PacketConn
	dnsServer *dns.Server
	// closing 在 mu 下置位，Serve 登记 socket 前检查它，迟到的 Serve 不得把服务器拉起来。
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
		system:      defaultSystemDNS,
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

	reply, err := s.forwardQuery(r)
	if err != nil {
		log.Debug("[DNS-FORWARD] forward query failed", "name", q.Name, "err", err)
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeServerFailure)
		_ = w.WriteMsg(m)
		return
	}

	// SetReply 会把 Rcode 重置成 NOERROR，上游的 NXDOMAIN 必须先存再写回：把"域名不存在"
	// 改写成 NOERROR 会让 LAN 客户端把否定应答当成解析成功。
	rcode := reply.Rcode
	reply.SetReply(r)
	reply.Rcode = rcode
	_ = w.WriteMsg(reply)
}

func (s *ForwardServer) forwardQuery(msg *dns.Msg) (*dns.Msg, error) {
	try := func(servers []string) (*dns.Msg, error) {
		return s.exchangeWithServers(servers, msg)
	}
	return QueryWithBuiltinFirst(s.dnsServers, s.systemDNSServers, s.system.Invalidate, try)
}

func (s *ForwardServer) exchangeWithServers(servers []string, msg *dns.Msg) (*dns.Msg, error) {
	if len(servers) == 0 {
		return nil, errors.New("no dns server available")
	}

	// 并发查询全部上游并取第一个权威应答，整个查询共享一个超时预算：串行扫描会让一个
	// 挂起的上游吃掉客户端整个读超时。只有没有任何上游给出权威应答（NOERROR/NXDOMAIN）
	// 时才返回 error——它同时是"整份列表不可达、缓存可能属于上一个网络"的判据。
	ctx, cancel := context.WithTimeout(context.Background(), s.client.Timeout)
	defer cancel()

	type result struct {
		reply *dns.Msg
		err   error
	}
	ch := make(chan result, len(servers))
	for _, server := range servers {
		go func(server string) {
			// Pack 会写 OPT 的 TTL（扩展 RCODE），共享 msg 会让并发分支竞争同一字段。
			reply, err := s.exchangeOne(ctx, msg.Copy(), server)
			ch <- result{reply: reply, err: err}
		}(server)
	}

	var (
		lastErr error
		// NXDOMAIN 要等正应答：并行竞速下先到的否定应答会把另一台解析器的正确结果挤掉。
		negative *dns.Msg
	)
	for range servers {
		select {
		case r := <-ch:
			switch {
			case r.err != nil:
				lastErr = r.err
			case r.reply == nil:
				lastErr = errors.New("dns: empty reply")
			case r.reply.Rcode == dns.RcodeSuccess:
				// 上游可能返回"OPT 在 ANSWER 段"的畸形 EDNS0 应答：不规范化则严格解析器判畸形、
				// 宽松解析器拿不到地址。
				NormalizeEDNS0Answer(r.reply)
				return r.reply, nil
			case r.reply.Rcode == dns.RcodeNameError:
				if negative == nil {
					NormalizeEDNS0Answer(r.reply)
					negative = r.reply
				}
			default:
				lastErr = fmt.Errorf("dns: server returned %s", dns.RcodeToString[r.reply.Rcode])
			}
		case <-ctx.Done():
			if negative != nil {
				return negative, nil
			}
			return nil, ctx.Err()
		}
	}

	if negative != nil {
		return negative, nil
	}
	if lastErr == nil {
		lastErr = errors.New("no dns server available")
	}
	return nil, lastErr
}

// exchangeOne 用 ctx 可取消的连接完成一次查询：首个上游成功后 cancel 其余分支时必须
// 立即关闭 socket，否则它们会一直阻塞到 dns.Client.Timeout。
func (s *ForwardServer) exchangeOne(ctx context.Context, msg *dns.Msg, server string) (*dns.Msg, error) {
	conn, err := s.client.DialContext(ctx, server)
	if err != nil {
		return nil, err
	}
	defer conn.Close() //nolint:errcheck

	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	reply, _, err := s.client.ExchangeWithConnContext(ctx, msg, conn)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, err
	}
	return reply, nil
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
