package proxy

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"
	clientconfig "github.com/nange/easyss/v3/client/config"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/stats"
)

// tcpDNSSession 持有一条 TCP DNS 连接生命周期内复用的代理上游交换。只有代理分支
// （经隧道到 clientconfig.ProxyDNSServer）使用它；直连分支每个查询独立拨号。
type tcpDNSSession struct {
	d   *dnsInterceptor
	key string
	// src 是客户端地址，只用于日志（与 UDP 路径的 [DNS_*] 日志字段保持一致）。
	src string
	ue  *UDPExchange
}

// newTCPSession 为一条 TCP DNS 连接建立会话。key 只需在本进程内唯一标识这条连接的
// 上游交换：RemoteAddr 对每条 TCP 连接唯一，ProxyDNSServer 只是命名空间标记。
func (d *dnsInterceptor) newTCPSession(remote net.Addr) *tcpDNSSession {
	return &tcpDNSSession{
		d:   d,
		key: fmt.Sprintf("tcp_dns://%s->%s", remote, clientconfig.ProxyDNSServer),
		// %v 而非 remote.String()：remote 允许为 nil，nil 接口上调用 String 会 panic。
		src: fmt.Sprintf("%v", remote),
	}
}

// invalidate 把失效的交换从会话池移除并关闭，使下一次查询重建新交换；解析失败路径与
// 连接结束共用。removeExchange 只删除仍指向本交换的条目，避免误删并发重建后的新交换。
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

// resolve 处理单条 TCP DNS 查询：Block/缓存/直连三条同步分支交给共享执行器
// （dns_exec.go），代理分支由本前端同步等待；后处理统一走 finishProxied，与 UDP 路径同一段代码。
func (s *tcpDNSSession) resolve(msg *dns.Msg, target string) (*dns.Msg, error) {
	d := s.d
	plan := d.plan(msg)
	ex := dnsExchange{plan: plan, src: s.src, dst: target}

	if plan.action != dnsActionProxy {
		return d.executeSync(ex, msg, target)
	}

	log.Debug("[DNS_PROXY]", "domain", plan.domain, "qtype", plan.qtype,
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

// resolveProxy 把查询经隧道发给 clientconfig.ProxyDNSServer 并同步等待应答。刻意忽略客户端请求
// 的解析器地址：走代理就是为了让查询在隧道出口发出，避免解析器降级到 TCP 时把明文发到墙内。
// 交换在连接内复用，每次查询都要显式发送，只有"创建时首载荷已并入引导记录"那次例外。
func (s *tcpDNSSession) resolveProxy(msg *dns.Msg) (*dns.Msg, error) {
	// 与 UDP 代理路径共用同一段准备逻辑：钳制 EDNS0 并重新封包。
	data, err := prepareProxied(msg, nil)
	if err != nil {
		return nil, err
	}

	ue := s.ue
	if ue == nil {
		acquired, created, err := s.d.pool.acquireExchange(context.Background(), s.key, clientconfig.ProxyDNSServer, data)
		if err != nil {
			return nil, err
		}
		ue = acquired
		s.ue = ue
		if !created {
			// 交换已存在：首载荷未被合并，需显式发送。
			if err := ue.Send(data); err != nil {
				s.invalidate()
				return nil, err
			}
		}
	} else if err := ue.Send(data); err != nil {
		s.invalidate()
		return nil, err
	}

	resp, err := s.waitResponse(ue)
	if err != nil {
		// 交换疑似失效（超时/流错误）：必须从会话池移除并关闭，否则残留的已关闭交换
		// 会被 acquireExchange 直接命中，该连接后续代理查询永久 SERVFAIL。
		s.invalidate()
	}
	return resp, err
}

// waitResponse 同步等待应答，超时后关闭交换使阻塞的 Receive 退出（调用方随后会作废它）。
// ue 由调用方快照传入：等待期间不能让 Receive goroutine 读会被 invalidate 置空的会话字段。
// respTimeout 由构造期归一化保证为正，这里是同步等待上限，不是 UDP 路径的读空闲开关。
func (s *tcpDNSSession) waitResponse(ue *UDPExchange) (*dns.Msg, error) {
	type result struct {
		data []byte
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		data, err := ue.Receive()
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
		ue.Close() //nolint:errcheck
		return nil, errDNSResponseTimeout
	}
}
