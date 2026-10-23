package proxy

import (
	"context"
	"net"
	"time"

	"github.com/miekg/dns"
	"github.com/nange/easyss/v3/client/router"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/protocol"
	"github.com/nange/easyss/v3/util"
	"github.com/nange/easyss/v3/util/bytespool"
	"github.com/things-go/go-socks5/statute"
)

func (s *Socks5Server) handleUDP(relay *udpRelay, d *socks5Frame, data []byte) error {
	src := relay.datagramSource().String()
	dst := d.target

	host, port, err := net.SplitHostPort(dst)
	if err != nil {
		log.Debug("[UDP] malformed datagram target", "src", src, "target", dst, "err", err)
		return nil
	}

	// VPN 对端优先于后面所有"公网路径"的门禁（QUIC 屏蔽、IPv6 策略门、链路本地
	// 丢弃、53 拦截）：对端名与 overlay IP 都不是公网目标，这些策略与它们无关。
	// 顺序在这里是有实际后果的——`disable_quic` 会静默吞掉发往 443 的数据报，
	// 53 拦截会按"查询域名"把发往对端 53 的查询重新分流。
	if s.vpn != nil {
		if name, ok := s.vpn.Lookup(host); ok {
			return s.vpnUDPRelay(relay, dst, name, data)
		}
	}

	if s.disableQUIC && port == "443" {
		return nil
	}

	if s.router.ShouldIPV6Disable() && util.IsIPV6(host) {
		log.Warn("[UDP] ipv6 target rejected, ipv6 disabled", "target", dst)
		return nil
	}

	if isNonRelayableUDPTarget(host) {
		log.Debug("[UDP] link-local broadcast/multicast target dropped", "src", src, "target", dst)
		return nil
	}

	// DNS 拦截只针对 53 端口，与 TCP 路径的端口门控一致（见 Socks5Server.connectHandler）：
	// 只按"载荷能否解包成 DNS 查询"判定会连 NBNS(137)/LLMNR(5355)/mDNS(5353) 一起吞掉，
	// 把局域网主机名当成 DNS 查询经隧道送出去。DisableDNSIntercept 与 TCP 路径同源。
	if port == "53" && !s.disableDNSIntercept {
		msg := &dns.Msg{}
		if err := msg.Unpack(data); err == nil && isDNSQueryMsg(msg) {
			return s.handleDNS(relay, d, msg, data)
		}
	}

	return s.handleRegularUDP(relay, d, dst, data)
}

// 这些目的地只能由本机在物理接口上发出：已连接 socket 收不到响应者单播回来的应答，未绑定的
// socket 会形成 代理→直连→TUN→代理 的环路。子网广播是 global unicast，仍按直连中继。
func isNonRelayableUDPTarget(host string) bool {
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.Equal(net.IPv4bcast) || ip.IsMulticast() || ip.IsLinkLocalUnicast()
}

// 两条应答通道：同步分支用 msg，异步的代理分支用 raw。都按客户端请求的目标地址组帧，
// tun2socks 以它建 UDP 流键。
func (s *Socks5Server) handleDNS(relay *udpRelay, d *socks5Frame, msg *dns.Msg, data []byte) error {
	clientAddr := relay.datagramSource()
	return s.dns.handleUDPQuery(clientAddr, udpDNSQuery{
		raw: data,
		msg: msg,
		src: clientAddr.String(),
		dst: d.target,
		reply: udpReply{
			msg: func(m *dns.Msg) error {
				return s.responseDNSMsg(relay, m, d.target)
			},
			raw: func(replyData []byte) {
				s.sendToClient(relay, replyData, d.target)
			},
		},
	})
}

// DNS 应答的后处理在拦截器的 onData 回调里，这里只组帧；会话生命周期归 udpPool.receiveLoop。
func (s *Socks5Server) receiveLoop(ue *UDPExchange, relay *udpRelay, target, key string, respTimeout time.Duration) {
	s.udp.receiveLoop(ue, key, respTimeout, func(data []byte) {
		s.sendToClient(relay, data, target)
	})
}

// 必须用客户端请求时的目标地址组帧：tun2socks 以该地址建流键，不符的会被丢弃。
func (s *Socks5Server) sendToClient(relay *udpRelay, data []byte, target string) {
	frame, err := statute.NewDatagram(target, data)
	if err != nil {
		log.Debug("[UDP] build datagram", "target", target, "err", err)
		return
	}
	peer := relay.datagramSource()
	if peer == nil {
		return
	}
	if _, err := relay.socket.WriteToUDP(frame.Bytes(), peer); err != nil {
		log.Debug("[UDP] write to client", "err", err)
	}
}

func (s *Socks5Server) handleRegularUDP(relay *udpRelay, d *socks5Frame, dst string, data []byte) error {
	host, _, err := net.SplitHostPort(dst)
	if err != nil {
		return err
	}

	switch s.router.ClassifyHost(host).Rule {
	case router.HostRuleBlock:
		log.Info("[UDP_BLOCK] blocked", "host", host, "target", dst)
		return nil
	case router.HostRuleDirect:
		log.Info("[UDP_DIRECT]", "target", dst)
		return s.directUDPRelay(relay, dst, data)
	case router.HostRuleProxy:
		log.Info("[UDP_PROXY]", "target", dst)
		return s.proxyUDPRelay(relay, dst, data)
	}
	return nil
}

// vpnUDPRelay 把一条发往 VPN 对端的数据报送进隧道。它复用直连 UDP 的会话表与读
// 循环（见 udp_pool.go 的 acquireDirectWith），只替换拨号器——两边的会话形状完全
// 一样：一个 socket、一个读循环、一个活动时间戳。
//
// 会话键带 `vpn_` 前缀，因此它与同一目标上的直连会话、代理交换三者在池中互不
// 干扰；键里用对端的**规范名**而不是 dst，使"按名字访问"与"按 overlay IP 访问"
// 落在同一条流上。
//
// 键里必须带端口：一条 UDP ASSOCIATE 允许向任意目标发数据报（RFC 1928），而对端
// 在首个数据报里就把目标端口固化了（见 vpn/node 的目标头），因此"同一对端的两个
// 端口"必须是两条流——否则第二个端口的数据报会被投递到第一个端口上。
//
// dst 仍然是访问侧的原始目标：应答组帧必须用它（tun2socks 以客户端请求的目标地址
// 为 UDP 流建键，换个源地址的数据报会被丢弃，见 sendToClient）。
// udpTargetPort 取出 "host:port" 的端口部分，用于会话键。解析失败时回退到整个
// 目标串：宁可少一次合并，也不能让两条不同的目标共用一个键。
func udpTargetPort(target string) string {
	if _, port, err := net.SplitHostPort(target); err == nil {
		return port
	}
	return target
}

func (s *Socks5Server) vpnUDPRelay(relay *udpRelay, dst, peerName string, data []byte) error {
	log.Info("[UDP_VPN]", "target", dst, "peer", peerName)
	key := "vpn_" + relay.datagramSource().String() + "_" + peerName + "_" + udpTargetPort(dst)

	dc, ok := s.udp.directFor(key)
	if !ok {
		var err error
		var created bool
		dc, created, err = s.udp.acquireDirectWith(key, dst, func(ctx context.Context, _, addr string) (net.Conn, error) {
			return s.vpn.DialUDP(ctx, addr)
		})
		if err != nil {
			log.Error("[UDP_VPN] dial", "target", dst, "peer", peerName, "err", err)
			return err
		}
		// 读取循环由创建者启动（与会话池的约定一致：池只管理生命周期，不做 I/O）。
		if created {
			go s.directUDPReadLoop(relay, dst, key, dc)
		}
	}

	dc.lastSeen.Store(time.Now().UnixNano())
	_, err := dc.conn.Write(data)
	return err
}

func (s *Socks5Server) directUDPRelay(relay *udpRelay, dst string, data []byte) error {
	key := "direct_" + relay.datagramSource().String() + "_" + dst

	dc, ok := s.udp.directFor(key)
	if !ok {
		var err error
		var created bool
		dc, created, err = s.udp.acquireDirect(key, dst)
		if err != nil {
			return err
		}
		if created {
			go s.directUDPReadLoop(relay, dst, key, dc)
		}
	}

	dc.lastSeen.Store(time.Now().UnixNano())
	// 直连流量不计入速度计数器，upload_speed/download_speed 只统计隧道流量。
	_, err := dc.conn.Write(data)
	return err
}

func (s *Socks5Server) directUDPReadLoop(relay *udpRelay, dst, key string, dc *directUDPConn) {
	rc := dc.conn
	defer func() {
		rc.Close() //nolint:errcheck
		s.udp.removeDirect(key, dc)
	}()
	buf := bytespool.Get(protocol.MaxUDPDataSize)
	defer bytespool.MustPut(buf)
	// 读满整个池档位：n == len(readBuf) 说明被截断或恰好等于，都超过 MaxUDPDataSize，
	// 丢弃比把截断内容转发给应用更安全。
	readBuf := buf[:cap(buf)]
	for {
		_ = rc.SetReadDeadline(time.Now().Add(s.udpIdleTimeout))
		n, err := rc.Read(readBuf)
		if err != nil {
			if protocol.IsUDPMessageTooLong(err) {
				log.Warn("[UDP] dropping oversized datagram", "err", err)
				continue
			}
			return
		}
		if n > protocol.MaxUDPDataSize {
			log.Warn("[UDP] dropping oversized datagram", "n", n,
				"limit", protocol.MaxUDPDataSize, "truncated", n == len(readBuf))
			continue
		}
		dc.lastSeen.Store(time.Now().UnixNano())
		s.sendToClient(relay, readBuf[:n], dst)
	}
}

func (s *Socks5Server) proxyUDPRelay(relay *udpRelay, dst string, data []byte) error {
	key := relay.datagramSource().String() + "_" + dst

	ue, created, err := s.udp.acquireExchange(context.Background(), key, dst, data)
	if err != nil {
		log.Error("[UDP_PROXY] open exchange", "dst", dst, "err", err)
		return err
	}
	if created {
		// 非 DNS 的 UDP 不能给读空闲超时：纯上传流会合法地长时间沉默，只保留双向空闲回收器。
		go s.receiveLoop(ue, relay, dst, key, 0)
		return nil // 第一个载荷已在握手中发送（其上行记账见 OpenUDPExchange）
	}

	if err := ue.Send(data); err != nil {
		log.Error("[UDP_PROXY] send", "err", err)
		s.udp.removeExchange(key, ue)
		return err
	}
	return nil
}

func (s *Socks5Server) responseDNSMsg(relay *udpRelay, msg *dns.Msg, dst string) error {
	data, err := msg.Pack()
	if err != nil {
		return err
	}
	frame, err := statute.NewDatagram(dst, data)
	if err != nil {
		return err
	}
	peer := relay.datagramSource()
	if peer == nil {
		return errSocksServerClosed
	}
	_, err = relay.socket.WriteToUDP(frame.Bytes(), peer)
	return err
}
