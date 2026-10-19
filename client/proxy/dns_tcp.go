package proxy

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"
	"github.com/nange/easyss/v3/client/config"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/stats"
)

// tcpDNSSession 持有一条 TCP DNS 连接生命周期内复用的代理上游交换。只有代理
// 分支（经隧道到 config.ProxyDNSServer）使用它；直连分支每个查询独立拨号。
type tcpDNSSession struct {
	d   *dnsInterceptor
	key string
	// src 是客户端地址，只用于日志（与 UDP 路径的 [DNS_*] 日志字段保持一致）。
	src string
	ue  *UDPExchange
}

// newTCPSession 为一条 TCP DNS 连接建立会话。
//
// key 只需在本进程内唯一标识这条连接的上游交换：RemoteAddr 对每条 TCP 连接
// 唯一，ProxyDNSServer 只是命名空间标记（同一条连接只对应一个上游）。
func (d *dnsInterceptor) newTCPSession(remote net.Addr) *tcpDNSSession {
	return &tcpDNSSession{
		d:   d,
		key: fmt.Sprintf("tcp_dns://%s->%s", remote, config.ProxyDNSServer),
		// %v 而非 remote.String()：remote 允许为 nil（nil 接口上调用 String 会 panic），
		// 而日志不该为平台细节承担这个风险。
		src: fmt.Sprintf("%v", remote),
	}
}

// invalidate 把失效的交换从会话池中移除并关闭，置空 ue，使下一次查询重建
// 新交换。解析失败路径与连接结束（close）共用。只删除仍指向本交换的条目，
// 避免误删并发重建后的新交换。
func (s *tcpDNSSession) invalidate() {
	if s.ue == nil {
		return
	}
	s.d.pool.removeExchange(s.key, s.ue)
	s.ue = nil
}

func (s *tcpDNSSession) close() {
	s.invalidate()
}

// resolve 按查询域名解析单条 TCP DNS 查询：Block/缓存/直连三条同步分支交给
// 共享执行器（dns_exec.go），代理分支由本前端同步等待（一条连接顺序使用自己
// 的交换，因此 Receive 不会并发）。
//
// 结果的后处理——规范化、AAAA 剥离、写缓存、学习——由 finishProxied 统一完成，
// 与 UDP 路径是同一段代码。
func (s *tcpDNSSession) resolve(msg *dns.Msg, target string) (*dns.Msg, error) {
	d := s.d
	plan := d.plan(msg)
	ex := dnsExchange{plan: plan, src: s.src, dst: target}

	if plan.action != dnsActionProxy {
		return d.executeSync(ex, msg, target)
	}

	log.Info("[DNS_PROXY]", "domain", plan.domain, "qtype", plan.qtype,
		"src", s.src, "dst", target)
	stats.RecordDNSProxyQuery()
	resp, err := s.resolveProxy(msg)
	if err != nil {
		return nil, err
	}
	d.finishProxied(resp, plan.domain, s.src, target)
	resp.Id = msg.Id
	return resp, nil
}

// resolveProxy 把 DNS 查询经隧道发给 config.ProxyDNSServer（8.8.8.8:53），
// 同步等待应答。这里刻意忽略客户端请求的解析器地址：走代理的意义就是让查询在
// 隧道出口发出，避免解析器降级到 TCP 时把查询明文发到墙内。
// 会话在连接生命周期内复用同一个 UDP 交换；每次查询都必须发送，只有"创建时首
// 载荷已合并进引导记录"的那一次免于重复发送。
func (s *tcpDNSSession) resolveProxy(msg *dns.Msg) (*dns.Msg, error) {
	// 与 UDP 代理路径共用同一段准备逻辑：钳制 EDNS0 并重新封包。
	data, err := prepareProxied(msg, nil)
	if err != nil {
		return nil, err
	}

	if s.ue == nil {
		ue, created, err := s.d.pool.acquireExchange(context.Background(), s.key, config.ProxyDNSServer, data)
		if err != nil {
			return nil, err
		}
		s.ue = ue
		if !created {
			// 交换已存在：首载荷未被合并，需显式发送。
			if err := ue.Send(data); err != nil {
				s.invalidate()
				return nil, err
			}
		}
	} else if err := s.ue.Send(data); err != nil {
		s.invalidate()
		return nil, err
	}

	resp, err := s.waitResponse()
	if err != nil {
		// 交换疑似失效（超时/流错误）：从会话池移除并关闭，下一次查询重建新交换，
		// 否则残留的已关闭交换会被 acquireExchange 直接命中，导致该连接
		// 后续代理查询永久 SERVFAIL。
		s.invalidate()
	}
	return resp, err
}

// waitResponse 同步等待代理 DNS 交换返回一条应答，超时后关闭交换使阻塞
// 的 Receive 退出（调用方随后会作废该交换）。交换只被本连接顺序使用，因此
// Receive 不会并发。
//
// respTimeout 由构造期归一化保证为正（见 newDNSInterceptor）：它在此处是
// 同步等待的上限，而不是 UDP 路径上那个"<= 0 即关闭读空闲"的功能开关。
func (s *tcpDNSSession) waitResponse() (*dns.Msg, error) {
	type result struct {
		data []byte
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		data, err := s.ue.Receive()
		ch <- result{data: data, err: err}
	}()

	timer := time.NewTimer(s.d.respTimeout)
	defer timer.Stop()

	select {
	case r := <-ch:
		if r.err != nil {
			return nil, r.err
		}
		msg := &dns.Msg{}
		if err := msg.Unpack(r.data); err != nil {
			return nil, err
		}
		return msg, nil
	case <-timer.C:
		s.ue.Close() //nolint:errcheck
		return nil, errDNSResponseTimeout
	}
}
