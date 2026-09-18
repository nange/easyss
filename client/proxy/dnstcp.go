package proxy

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/nange/easyss/v3/client/config"
	"github.com/nange/easyss/v3/client/router"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/stats"
	"github.com/nange/easyss/v3/util"
	"github.com/txthinking/socks5"
)

// maxTCPDNSMessageLen 是 DNS over TCP 单条报文的最大长度。长度字段是 uint16，
// 理论上限 65535；这里再收紧一档，拒绝明显非 DNS 的畸形长度。
const maxTCPDNSMessageLen = 64 * 1024

// errDNSResponseTimeout 表示代理 DNS 上游在等待窗口内没有任何应答。
var errDNSResponseTimeout = errors.New("dns response timeout")

// bufferedConn 让已经用 bufio.Reader 预读过的连接重新作为普通 net.Conn 使用：
// Read 先消费缓冲区，再落到底层连接。
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) { return b.r.Read(p) }

// newBufferedConn 构造 bufferedConn；pending 是回退前已消耗的字节，会先于缓冲区的
// 其余内容被读出，保证回退中继不丢字节。
func newBufferedConn(c net.Conn, br *bufio.Reader, pending []byte) net.Conn {
	if len(pending) == 0 {
		return &bufferedConn{Conn: c, r: br}
	}
	return &bufferedConn{Conn: c, r: bufio.NewReader(io.MultiReader(bytes.NewReader(pending), br))}
}

// readFirstTCPDNS 从流中读取一条 DNS over TCP 报文（2 字节长度前缀 + DNS 报文），
// 并在失败时返回已消耗的字节：首条报文可能只是恰好落在 53 端口上的非 DNS 流量，
// 回退中继必须把这些字节原样还给目标。
//
// touch 在长度前缀读完后调用一次，让调用方按读取进度续期读截止时间：否则整条
// 报文（最长 64KB）会被塞进一个固定的首读窗口，慢速滴水即可长期占住 goroutine。
func readFirstTCPDNS(br *bufio.Reader, touch func()) (msg *dns.Msg, consumed []byte, err error) {
	var lenBuf [2]byte
	if _, err := io.ReadFull(br, lenBuf[:]); err != nil {
		return nil, nil, err
	}
	consumed = append(consumed, lenBuf[:]...)
	length := int(lenBuf[0])<<8 | int(lenBuf[1])
	if length == 0 || length > maxTCPDNSMessageLen {
		return nil, consumed, fmt.Errorf("dns tcp message length %d out of range", length)
	}

	if touch != nil {
		touch()
	}
	data := make([]byte, length)
	n, err := io.ReadFull(br, data)
	consumed = append(consumed, data[:n]...)
	if err != nil {
		return nil, consumed, err
	}
	msg = &dns.Msg{}
	if err := msg.Unpack(data); err != nil {
		return nil, consumed, err
	}
	return msg, consumed, nil
}

// readTCPDNSMessage 读取后续（可丢弃）的一条 DNS over TCP 报文，语义与
// readFirstTCPDNS 相同但不关心已消耗字节，由后者兜住读取逻辑。
func readTCPDNSMessage(br *bufio.Reader, touch func()) (*dns.Msg, error) {
	msg, _, err := readFirstTCPDNS(br, touch)
	return msg, err
}

// writeTCPDNSMessage 以 DNS over TCP 帧格式写出一条应答。
func writeTCPDNSMessage(w io.Writer, msg *dns.Msg) error {
	data, err := msg.Pack()
	if err != nil {
		return err
	}
	// 长度字段是 uint16：超出会静默回绕。上游为 UDP 交换时实际不可达，
	// 这里做防御性拒绝。
	if len(data) > 0xffff {
		return fmt.Errorf("dns tcp message too large: %d bytes", len(data))
	}
	buf := make([]byte, 0, len(data)+2)
	buf = append(buf, byte(len(data)>>8), byte(len(data)))
	buf = append(buf, data...)
	_, err = w.Write(buf)
	return err
}

// touchReadDeadline 返回一个把连接读截止时间续期 timeout 的回调，供读帧函数
// 在读取过程中按进度调用。续期失败无从报告（读帧函数只返回协议错误），因此
// 忽略；真正的连接错误会在随后的 Read 上暴露。
func touchReadDeadline(c net.Conn, timeout time.Duration) func() {
	return func() { _ = c.SetReadDeadline(time.Now().Add(timeout)) }
}

// tcpDNSUpstream 持有 TCP DNS 连接生命周期内复用的代理上游交换。只有代理分支
// （经隧道到 config.ProxyDNSServer）使用它；直连分支每个查询独立拨号。
type tcpDNSUpstream struct {
	s   *Socks5Server
	key string
	ue  *UDPExchange
}

// invalidate 把失效的交换从 s.udpExch 中移除并关闭，置空 ue，使下一次查询重建
// 新交换。连接结束（close）与解析失败路径共用。只删除仍指向本交换的条目，
// 避免误删并发重建后的新交换。
func (u *tcpDNSUpstream) invalidate() {
	if u.ue == nil {
		return
	}
	u.s.udpMu.Lock()
	if cur, ok := u.s.udpExch[u.key]; ok && cur == u.ue {
		delete(u.s.udpExch, u.key)
	}
	u.s.udpMu.Unlock()
	u.ue.Close() //nolint:errcheck
	u.ue = nil
}

func (u *tcpDNSUpstream) close() {
	u.invalidate()
}

// handleTCPDNS 拦截发往 53 端口的 TCP 连接，按查询域名分流应答
// （与 UDP 的 handleDNS 行为一致）。首条报文无法解析为 DNS 查询时，
// 回退到按目标 IP 的普通中继（已读字节还给流）。
func (s *Socks5Server) handleTCPDNS(c net.Conn, r *socks5.Request, target, host string) error {
	br := bufio.NewReader(c)

	// 扫雷式首读：只要首条报文没被确认为 DNS 查询，最终都会走按目标 IP 的普通
	// 中继，因此这里只受一个宽限期约束——连接建立后完全不发数据的客户端不应挂住
	// 本 goroutine。该窗口在读到长度前缀后按进度续期，覆盖载荷读取；一旦确认是
	// DNS 查询，之后的空闲计时改由 tcpDNSIdleTimeout 承担。
	if err := c.SetReadDeadline(time.Now().Add(s.streamIdleTimeout)); err != nil {
		return err
	}
	touch := touchReadDeadline(c, s.streamIdleTimeout)

	first, consumed, err := readFirstTCPDNS(br, touch)
	if err != nil {
		if errors.Is(err, io.EOF) {
			// 客户端连上后立即关闭：无事可做。
			return nil
		}
		log.Debug("[TCP_DNS] first message unreadable, fallback to relay", "target", target, "err", err)
		return s.fallbackTCPDNS(c, br, consumed, r, target, host)
	}
	if !isDNSQueryMsg(first) {
		log.Debug("[TCP_DNS] first message is not a dns query, fallback to relay", "target", target)
		return s.fallbackTCPDNS(c, br, consumed, r, target, host)
	}

	// 是 DNS 查询：先回 SOCKS5 成功应答，再逐条处理。
	if err := writeSocksSuccessReply(c); err != nil {
		return err
	}

	// key 只需在本进程内唯一标识这条连接的上游交换：RemoteAddr 对每条 TCP 连接
	// 唯一，ProxyDNSServer 只是命名空间标记（同一条连接只对应一个上游）。
	up := &tcpDNSUpstream{
		s:   s,
		key: fmt.Sprintf("tcp_dns://%s->%s", c.RemoteAddr(), config.ProxyDNSServer),
	}
	defer up.close()

	msg := first
	for {
		resp, err := s.resolveTCPDNSQuery(msg, up, target)
		if err != nil {
			// 上游解析失败：回 SERVFAIL，连接继续，让客户端自行重试。
			log.Warn("[TCP_DNS] resolve", "target", target, "err", err)
			resp = new(dns.Msg)
			resp.SetRcode(msg, dns.RcodeServerFailure)
		}
		if resp == nil {
			resp = new(dns.Msg)
			resp.SetRcode(msg, dns.RcodeServerFailure)
		}
		if err := writeTCPDNSMessage(c, resp); err != nil {
			return err
		}

		if err := c.SetReadDeadline(time.Now().Add(s.tcpDNSIdleTimeout())); err != nil {
			return err
		}
		msg, err = readTCPDNSMessage(br, touchReadDeadline(c, s.tcpDNSIdleTimeout()))
		if err != nil {
			// EOF/超时/对端关闭：连接结束。
			return nil
		}
		if !isDNSQueryMsg(msg) {
			return nil
		}
	}
}

// fallbackTCPDNS 在首条报文无法识别为 DNS 查询时，把连接交回按目标 IP 的
// 普通分流（已读字节通过 pending 还给流），并清除本路径设置的读截止时间。
func (s *Socks5Server) fallbackTCPDNS(c net.Conn, br *bufio.Reader, pending []byte, r *socks5.Request, target, host string) error {
	_ = c.SetReadDeadline(time.Time{})
	return s.routeTCP(newBufferedConn(c, br, pending), r, target, host)
}

// tcpDNSIdleTimeout 是 TCP DNS 拦截逐条查询之间的读空闲超时。复用 UDP 会话的
// 空闲语义（2 倍 base），避免把保持长连接的解析器过早断开（如 DNSResp 的
// base/3 = 10s 级别）。
func (s *Socks5Server) tcpDNSIdleTimeout() time.Duration {
	if s.udpIdleTimeout > 0 {
		return s.udpIdleTimeout
	}
	return 30 * time.Second
}

// resolveTCPDNSQuery 按查询域名解析单条 DNS 查询：Block 本地屏蔽，
// Direct/服务器域名用 target（客户端请求的解析器）直连解析，其余经隧道到
// config.ProxyDNSServer。结果写入 dnsCache（A/AAAA）并按自定义域名规则学习。
func (s *Socks5Server) resolveTCPDNSQuery(msg *dns.Msg, up *tcpDNSUpstream, target string) (*dns.Msg, error) {
	q := msg.Question[0]
	domain := strings.TrimSuffix(q.Name, ".")
	qtype := dns.TypeToString[q.Qtype]

	rule := s.router.MatchHostRule(domain)
	if rule == router.HostRuleBlock {
		log.Info("[DNS_BLOCK] blocked", "domain", domain, "qtype", qtype)
		return blockedDNSReply(msg), nil
	}

	isDirect := s.isServerDomain(domain) || rule == router.HostRuleDirect
	if cached := s.dnsCache.Get(q.Name, qtype, isDirect); cached != nil {
		log.Info("[DNS_CACHE] hit", "domain", domain, "qtype", qtype, "direct", isDirect)
		if s.router.ShouldIPV6Disable() && q.Qtype == dns.TypeAAAA {
			cached.Answer = nil
		}
		cached.Id = msg.Id
		return cached, nil
	}

	if isDirect {
		log.Info("[DNS_DIRECT]", "domain", domain, "qtype", qtype)
		stats.RecordDNSDirectQuery()
		resp, err := s.resolveDirectDNS(msg, domain, target)
		if err != nil {
			return nil, err
		}
		log.Info("[DNS_DIRECT] result", "domain", domain, "qtype", qtype, "answers", util.DNSAnswerStrings(resp))
		resp.Id = msg.Id
		return resp, nil
	}

	log.Info("[DNS_PROXY]", "domain", domain, "qtype", qtype)
	stats.RecordDNSProxyQuery()
	resp, err := s.resolveProxyDNS(msg, up)
	if err != nil {
		return nil, err
	}
	log.Info("[DNS_PROXY] result", "domain", domain, "qtype", qtype, "answers", util.DNSAnswerStrings(resp))
	if s.router.ShouldIPV6Disable() && q.Qtype == dns.TypeAAAA {
		resp.Answer = nil
	}
	_ = s.dnsCache.Set(resp, false)
	s.learnDNSAnswers(resp, domain, false)
	resp.Id = msg.Id
	return resp, nil
}

// resolveProxyDNS 把 DNS 查询经隧道发给 config.ProxyDNSServer（8.8.8.8:53），
// 同步等待应答。这里刻意忽略客户端请求的解析器地址：走代理的意义就是让查询在
// 隧道出口发出，避免解析器降级到 TCP 时把查询明文发到墙内。
// up 在连接生命周期内复用同一个 UDP 交换；每次查询都必须发送，只有"创建时首
// 载荷已合并进引导记录"的那一次免于重复发送。
func (s *Socks5Server) resolveProxyDNS(msg *dns.Msg, up *tcpDNSUpstream) (*dns.Msg, error) {
	data, err := msg.Pack()
	if err != nil {
		return nil, err
	}

	if up.ue == nil {
		ue, created, err := s.getOrCreateUDPExchange(context.Background(), up.key, config.ProxyDNSServer, data)
		if err != nil {
			return nil, err
		}
		up.ue = ue
		if !created {
			// 交换已存在：首载荷未被合并，需显式发送。
			if err := ue.Send(data); err != nil {
				up.invalidate()
				return nil, err
			}
		}
	} else if err := up.ue.Send(data); err != nil {
		up.invalidate()
		return nil, err
	}

	resp, err := s.waitUDPDNSResponse(up.ue)
	if err != nil {
		// 交换疑似失效（超时/流错误）：从 map 移除并关闭，下一次查询重建新交换，
		// 否则残留的已关闭交换会被 getOrCreateUDPExchange 直接命中，导致该连接
		// 后续代理查询永久 SERVFAIL。
		up.invalidate()
	}
	return resp, err
}

// waitUDPDNSResponse 同步等待代理 DNS 交换返回一条应答，超时后关闭交换使阻塞
// 的 Receive 退出（调用方随后会作废该交换）。交换只被本连接顺序使用，因此
// Receive 不会并发。
func (s *Socks5Server) waitUDPDNSResponse(ue *UDPExchange) (*dns.Msg, error) {
	timeout := s.dnsRespTimeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	type result struct {
		data []byte
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		data, err := ue.Receive()
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
		ue.Close() //nolint:errcheck
		return nil, errDNSResponseTimeout
	}
}
