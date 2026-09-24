package proxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"
	"github.com/nange/easyss/v3/client/config"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/stats"
	"github.com/nange/easyss/v3/util"
)

// errDNSResponseTimeout 表示代理 DNS 上游在等待窗口内没有任何应答。
var errDNSResponseTimeout = errors.New("dns response timeout")

// tcpDNSSession 持有一条 TCP DNS 连接生命周期内复用的代理上游交换。只有代理
// 分支（经隧道到 config.ProxyDNSServer）使用它；直连分支每个查询独立拨号。
type tcpDNSSession struct {
	d   *dnsInterceptor
	key string
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
	}
}

// invalidate 把失效的交换从会话池中移除并关闭，置空 ue，使下一次查询重建
// 新交换。解析失败路径与连接结束（close）共用。只删除仍指向本交换的条目，
// 避免误删并发重建后的新交换。
func (s *tcpDNSSession) invalidate() {
	if s.ue == nil {
		return
	}
	s.d.pool.invalidateExchange(s.key, s.ue)
	s.ue = nil
}

func (s *tcpDNSSession) close() {
	s.invalidate()
}

// resolve 按查询域名解析单条 TCP DNS 查询：Block 本地屏蔽，
// Direct/服务器域名用 target（客户端请求的解析器）直连解析，其余经隧道到
// config.ProxyDNSServer。结果写入缓存（代理分支）并按自定义域名规则学习。
// 分流判定与 UDP 路径共用 dnsInterceptor.plan。
func (s *tcpDNSSession) resolve(msg *dns.Msg, target string) (*dns.Msg, error) {
	d := s.d
	plan := d.plan(msg)
	switch plan.action {
	case dnsActionBlock:
		log.Info("[DNS_BLOCK] blocked", "domain", plan.domain, "qtype", plan.qtype)
		return blockedDNSReply(msg), nil
	case dnsActionCacheHit:
		return plan.cached, nil
	case dnsActionDirect:
		log.Info("[DNS_DIRECT]", "domain", plan.domain, "qtype", plan.qtype)
		stats.RecordDNSDirectQuery()
		resp, err := d.resolveDirectDNS(msg, plan.domain, target)
		if err != nil {
			return nil, err
		}
		log.Info("[DNS_DIRECT] result", "domain", plan.domain, "qtype", plan.qtype, "answers", util.DNSAnswerStrings(resp))
		resp.Id = msg.Id
		return resp, nil
	default:
		log.Info("[DNS_PROXY]", "domain", plan.domain, "qtype", plan.qtype)
		stats.RecordDNSProxyQuery()
		resp, err := s.resolveProxy(msg)
		if err != nil {
			return nil, err
		}
		log.Info("[DNS_PROXY] result", "domain", plan.domain, "qtype", plan.qtype, "answers", util.DNSAnswerStrings(resp))
		if d.router.ShouldIPV6Disable() && msg.Question[0].Qtype == dns.TypeAAAA {
			resp.Answer = nil
		}
		_ = d.cache.Set(resp, false)
		d.learnDNSAnswers(resp, plan.domain, false)
		resp.Id = msg.Id
		return resp, nil
	}
}

// resolveProxy 把 DNS 查询经隧道发给 config.ProxyDNSServer（8.8.8.8:53），
// 同步等待应答。这里刻意忽略客户端请求的解析器地址：走代理的意义就是让查询在
// 隧道出口发出，避免解析器降级到 TCP 时把查询明文发到墙内。
// 会话在连接生命周期内复用同一个 UDP 交换；每次查询都必须发送，只有"创建时首
// 载荷已合并进引导记录"的那一次免于重复发送。
func (s *tcpDNSSession) resolveProxy(msg *dns.Msg) (*dns.Msg, error) {
	data, err := msg.Pack()
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
func (s *tcpDNSSession) waitResponse() (*dns.Msg, error) {
	timeout := s.d.respTimeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	type result struct {
		data []byte
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		data, err := s.ue.Receive()
		ch <- result{data: data, err: err}
	}()

	timer := time.NewTimer(timeout)
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
