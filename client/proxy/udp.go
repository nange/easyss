package proxy

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/miekg/dns"
	"github.com/nange/easyss/v3/client/router"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/protocol"
	"github.com/nange/easyss/v3/shaper"
	"github.com/nange/easyss/v3/util"
	"github.com/nange/easyss/v3/util/bytespool"
	"github.com/things-go/go-socks5/statute"
)

func (s *Socks5Server) handleUDP(relay *udpRelay, d *socks5Frame, data []byte) error {
	// 每个数据报只做一次 String()：它既是直连/代理池的键，也是 DNS 日志的 src。
	clientAddr := relay.datagramSource()
	src := clientAddr.String()
	dst := d.target

	host, port, err := net.SplitHostPort(dst)
	if err != nil {
		log.Debug("[UDP] malformed datagram target", "src", src, "target", dst, "err", err)
		return nil
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

	// DNS 拦截只认 53 端口：只按"载荷能否解包成 DNS 查询"判定会吞掉 NBNS/LLMNR/mDNS ——
	// NBNS 查询在线格式里就是单标签、QTYPE=32，会被当成 DNS 经隧道送出，泄漏局域网主机名。
	if port == "53" {
		msg := &dns.Msg{}
		if err := msg.Unpack(data); err == nil && isDNSQueryMsg(msg) {
			return s.handleDNS(relay, d, msg, data, clientAddr, src)
		}
	}

	return s.handleRegularUDP(relay, d, dst, data, src)
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
func (s *Socks5Server) handleDNS(relay *udpRelay, d *socks5Frame, msg *dns.Msg, data []byte, clientAddr *net.UDPAddr, src string) error {
	return s.dns.handleUDPQuery(clientAddr, udpDNSQuery{
		raw: data,
		msg: msg,
		src: src,
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

func (s *Socks5Server) handleRegularUDP(relay *udpRelay, d *socks5Frame, dst string, data []byte, src string) error {
	host, _, err := net.SplitHostPort(dst)
	if err != nil {
		return err
	}

	cls := s.udpRoutes.classify(s.router, host)
	switch cls.Rule {
	case router.HostRuleBlock:
		log.Debug("[UDP_BLOCK] blocked", "host", host, "target", dst, "src", src)
		return nil
	case router.HostRuleDirect:
		log.Debug("[UDP_DIRECT]", "target", dst)
		return s.directUDPRelay(relay, dst, data, src)
	case router.HostRuleProxy:
		log.Debug("[UDP_PROXY]", "target", dst)
		return s.proxyUDPRelay(relay, dst, data, src)
	}
	return nil
}

func (s *Socks5Server) directUDPRelay(relay *udpRelay, dst string, data []byte, src string) error {
	key := "direct_" + src + "_" + dst

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
	// 不设读 deadline：目标长期不回应不代表会话空闲，纯上行流合法。回收由 cleanupLoop
	// 按 lastSeen 判定，close 该 socket 会唤醒阻塞中的 Read。
	for {
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

func (s *Socks5Server) proxyUDPRelay(relay *udpRelay, dst string, data []byte, src string) error {
	key := src + "_" + dst

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
		// 快路径取到交换后，回收/驱逐/DNS 超时可能已把它关闭；这是正常收尾竞态，不是发送故障。
		if errors.Is(err, shaper.ErrClosed) {
			log.Debug("[UDP_PROXY] send on closed exchange", "dst", dst)
			s.udp.removeExchange(key, ue)
			return nil
		}
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
