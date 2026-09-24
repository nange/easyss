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
	"github.com/txthinking/socks5"
)

func (s *Socks5Server) handleUDP(srv *socks5.Server, clientAddr *net.UDPAddr, d *socks5.Datagram) error {
	src := clientAddr.String()
	dst := d.Address()

	host, port, err := net.SplitHostPort(dst)
	if err != nil {
		// 畸形数据报目标：直接丢弃，而不是用一个服务器反正会拒绝的空目标
		// 打开交换。
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

	msg := &dns.Msg{}
	if err := msg.Unpack(d.Data); err == nil && isDNSQueryMsg(msg) {
		return s.handleDNS(srv, clientAddr, d, msg)
	}

	return s.handleRegularUDP(srv, clientAddr, d, dst)
}

// handleDNS 把一条 DNS 查询交给拦截器，并为它准备两条应答通道：同步分支用
// msg 通道（直接写回一条应答），异步的代理分支用 raw 通道（应答由 receiveLoop
// 在任意时刻送回）。两者的组帧都按客户端请求的目标地址进行——透明 NAT
// （tun2socks）以该地址为 UDP 流建键，声称来自上游地址的数据报会被丢弃。
func (s *Socks5Server) handleDNS(srv *socks5.Server, clientAddr *net.UDPAddr, d *socks5.Datagram, msg *dns.Msg) error {
	return s.dns.handleUDPQuery(clientAddr, udpDNSQuery{
		raw: d.Data,
		msg: msg,
		dst: d.Address(),
		reply: udpReply{
			msg: func(m *dns.Msg) error {
				return responseDNSMsg(srv.UDPConn, clientAddr, m, d.Address())
			},
			raw: func(data []byte) {
				s.sendToClient(srv, clientAddr, data, d.Address())
			},
		},
	})
}

// receiveLoop 把代理交换收到的数据报按 SOCKS5 帧发回客户端，直到交换失败或被
// 回收。DNS 应答的后处理（AAAA 剥离、写缓存、学习）由拦截器在 dns_udp.go 的
// onData 回调里完成，这里只做组帧。
//
// 会话生命周期（读空闲定时器、退出时的地图清理与关闭）由 udpPool.receiveLoop
// 承担，本函数只提供「收到数据报之后做什么」。
func (s *Socks5Server) receiveLoop(ue *UDPExchange, srv *socks5.Server, clientAddr *net.UDPAddr, target, key string, respTimeout time.Duration) {
	s.udp.receiveLoop(ue, key, respTimeout, func(data []byte) {
		s.sendToClient(srv, clientAddr, data, target)
	})
}

func (s *Socks5Server) sendToClient(srv *socks5.Server, clientAddr *net.UDPAddr, data []byte, target string) {
	a, addr, port, err := socks5.ParseAddress(target)
	if err != nil {
		return
	}
	if a == socks5.ATYPDomain {
		addr = addr[1:]
	}
	resp := socks5.NewDatagram(a, addr, port, data)
	if _, err := srv.UDPConn.WriteToUDP(resp.Bytes(), clientAddr); err != nil {
		log.Debug("[UDP] write to client", "err", err)
	}
}

func (s *Socks5Server) handleRegularUDP(srv *socks5.Server, clientAddr *net.UDPAddr, d *socks5.Datagram, dst string) error {
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
		return s.directUDPRelay(srv, clientAddr, d, dst)
	case router.HostRuleProxy:
		log.Info("[UDP_PROXY]", "target", dst)
		return s.proxyUDPRelay(srv, clientAddr, d, dst)
	}
	return nil
}

func (s *Socks5Server) directUDPRelay(srv *socks5.Server, clientAddr *net.UDPAddr, d *socks5.Datagram, dst string) error {
	key := "direct_" + clientAddr.String() + "_" + dst

	dc, ok := s.udp.directFor(key)
	if !ok {
		var err error
		var created bool
		dc, created, err = s.udp.acquireDirect(key, dst)
		if err != nil {
			return err
		}
		// 读取循环由创建者启动：会话池只管理生命周期，不做任何 I/O。
		if created {
			go s.directUDPReadLoop(srv, clientAddr, dst, key, dc)
		}
	}

	dc.lastSeen.Store(time.Now().UnixNano())
	_, err := dc.conn.Write(d.Data)
	return err
}

// directUDPReadLoop 把来自直连远端的数据库报中继回客户端，直到 socket 失败或
// 读空闲截止时间在无数据的情况下触发。该截止时间与清理循环用于回收空闲会话的
// udpIdleTimeout 相同（用户配置超时的 2 倍），镜像服务端 UDP 处理器——它同样以
// 2 倍超时的空闲截止时间读取。退出时会关闭 socket 并从会话表中移除自己的条目，
// 但仅在条目仍指向本会话时——绝不会移除指向替换它的新会话的条目。
func (s *Socks5Server) directUDPReadLoop(srv *socks5.Server, clientAddr *net.UDPAddr, dst, key string, dc *directUDPConn) {
	rc := dc.conn
	defer func() {
		rc.Close() //nolint:errcheck
		s.udp.removeDirect(key, dc)
	}()
	buf := bytespool.Get(protocol.MaxUDPDataSize)
	defer bytespool.MustPut(buf)
	for {
		_ = rc.SetReadDeadline(time.Now().Add(s.udpIdleTimeout))
		n, err := rc.Read(buf)
		if err != nil {
			return
		}
		// 接收时也刷新空闲时间戳，与发送一致，镜像代理路径
		// （UDPExchange.Receive）：一个只持续接收而不再写入的流（一次查询带来
		// 一长串响应）在仍然活跃时不能被回收。
		dc.lastSeen.Store(time.Now().UnixNano())
		s.sendToClient(srv, clientAddr, buf[:n], dst)
	}
}

func (s *Socks5Server) proxyUDPRelay(srv *socks5.Server, clientAddr *net.UDPAddr, d *socks5.Datagram, dst string) error {
	key := clientAddr.String() + "_" + dst

	ue, created, err := s.udp.acquireExchange(context.Background(), key, dst, d.Data)
	if err != nil {
		log.Error("[UDP_PROXY] open exchange", "dst", dst, "err", err)
		return err
	}
	if created {
		// 非 DNS 的 UDP 不能使用较短的读空闲超时：会话可能合法地长时间沉默
		// （例如纯上传流），因此它只保留默认 60 秒的双向空闲回收器。
		go s.receiveLoop(ue, srv, clientAddr, dst, key, 0)
		return nil // 第一个载荷已在握手中发送
	}

	if err := ue.Send(d.Data); err != nil {
		log.Error("[UDP_PROXY] send", "err", err)
		s.udp.removeExchange(key, ue)
		return err
	}
	return nil
}

func responseDNSMsg(conn *net.UDPConn, addr *net.UDPAddr, msg *dns.Msg, dst string) error {
	data, err := msg.Pack()
	if err != nil {
		return err
	}
	a, addrBytes, port, err := socks5.ParseAddress(dst)
	if err != nil {
		return err
	}
	if a == socks5.ATYPDomain {
		addrBytes = addrBytes[1:]
	}
	resp := socks5.NewDatagram(a, addrBytes, port, data)
	_, err = conn.WriteToUDP(resp.Bytes(), addr)
	return err
}
