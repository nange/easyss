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
		// 畸形数据报目标：直接丢弃，而不是用一个服务器反正会拒绝的空目标
		// 打开交换。
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

	// 链路本地专用的目的地不进中继路径，见 isNonRelayableUDPTarget。
	if isNonRelayableUDPTarget(host) {
		log.Debug("[UDP] link-local broadcast/multicast target dropped", "src", src, "target", dst)
		return nil
	}

	// DNS 拦截只针对 53 端口，与 TCP 路径的端口门控一致（见 Socks5Server.connectHandler）。
	// 只按"载荷能否解包成 DNS 查询"判定会连 NBNS(137)/LLMNR(5355)/mDNS(5353) 一起吞掉：
	// NBNS 查询在 DNS 线格式里就是 QNAME 为 NetBIOS first-level 编码的单标签、
	// QTYPE=32（DNS 类型表里是 NIMLOC），于是被当成 DNS 查询经隧道送到
	// config.ProxyDNSServer 解析——局域网主机名被泄漏给代理与公共 DNS，客户端还会
	// 拿着一个假的否定应答当作 NBNS 服务器的回复。非 53 端口按普通 UDP 分流。
	if port == "53" {
		msg := &dns.Msg{}
		if err := msg.Unpack(data); err == nil && isDNSQueryMsg(msg) {
			return s.handleDNS(relay, d, msg, data)
		}
	}

	return s.handleRegularUDP(relay, d, dst, data)
}

// isNonRelayableUDPTarget 报告 host 是否为"只能由本机在物理接口上发出"的目的地：
// 受限广播（255.255.255.255）、多播、链路本地单播。中继它们既没有意义也有害：
//
//   - 直连用的是 net.Dial 的已连接 socket，内核只接受来自该目标地址的数据报，而
//     广播/多播查询的应答来自响应者的单播地址，因此应答永远收不到；
//   - 直连拨号只对 global unicast 目标绑定物理接口（tun2socks dialer 主动跳过
//     受限广播与多播），未绑定的 socket 会按系统路由表把报文送回 TUN——TUN 的
//     /1../8 路由与各接口的广播路由里它的 metric 都更优——形成 代理→直连→TUN→代理
//     的环路，正是 client.Client 直连拨号器注释里警告的那个环路。
//
// 子网广播（192.168.1.255、TUN 的 198.18.255.255 等）不在此列：它们是 global
// unicast，直连拨号会绑定物理接口，历史上一直按直连中继（日志里出现的
// [UDP_DIRECT] target=198.18.255.255:137 即是），行为保持不变。
func isNonRelayableUDPTarget(host string) bool {
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.Equal(net.IPv4bcast) || ip.IsMulticast() || ip.IsLinkLocalUnicast()
}

// handleDNS 把一条 DNS 查询交给拦截器，并为它准备两条应答通道：同步分支用
// msg 通道（直接写回一条应答），异步的代理分支用 raw 通道（应答由 receiveLoop
// 在任意时刻送回）。两者的组帧都按客户端请求的目标地址进行——透明 NAT
// （tun2socks）以该地址为 UDP 流建键，声称来自上游地址的数据报会被丢弃。
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

// receiveLoop 把代理交换收到的数据报按 SOCKS5 帧发回客户端，直到交换失败或被
// 回收。DNS 应答的后处理（AAAA 剥离、写缓存、学习）由拦截器在 dns_udp.go 的
// onData 回调里完成，这里只做组帧。
//
// 会话生命周期（读空闲定时器、退出时的地图清理与关闭）由 udpPool.receiveLoop
// 承担，本函数只提供「收到数据报之后做什么」。
func (s *Socks5Server) receiveLoop(ue *UDPExchange, relay *udpRelay, target, key string, respTimeout time.Duration) {
	s.udp.receiveLoop(ue, key, respTimeout, func(data []byte) {
		s.sendToClient(relay, data, target)
	})
}

// sendToClient 把一条载荷按 SOCKS5 UDP 应答帧（RSV + FRAG + ATYP + ADDR + PORT
// + DATA）写回客户端。组帧必须使用客户端请求时的目标地址：透明 NAT
// （tun2socks）以该地址为 UDP 流建键，源地址不符的数据报会被丢弃。
func (s *Socks5Server) sendToClient(relay *udpRelay, data []byte, target string) {
	frame, err := statute.NewDatagram(target, data)
	if err != nil {
		log.Debug("[UDP] build datagram", "target", target, "err", err)
		return
	}
	peer := relay.datagramSource()
	if peer == nil {
		// 尚未收到过该客户端的任何数据报，无处可回。
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
// dst 仍然是访问侧的原始目标：应答组帧必须用它（tun2socks 以客户端请求的目标地址
// 为 UDP 流建键，换个源地址的数据报会被丢弃，见 sendToClient）。
func (s *Socks5Server) vpnUDPRelay(relay *udpRelay, dst, peerName string, data []byte) error {
	log.Info("[UDP_VPN]", "target", dst, "peer", peerName)
	key := "vpn_" + relay.datagramSource().String() + "_" + peerName

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
		// 读取循环由创建者启动：会话池只管理生命周期，不做任何 I/O。
		if created {
			go s.directUDPReadLoop(relay, dst, key, dc)
		}
	}

	dc.lastSeen.Store(time.Now().UnixNano())
	// 直连流量不计入速度计数器：托盘与 /stats 的 upload_speed/download_speed
	// 只统计经隧道的流量（见 UDPExchange.Send），直连 UDP 与直连 TCP
	// （route.go 的 relayTCP/copyHalfClose）在这一口径上保持一致。
	_, err := dc.conn.Write(data)
	return err
}

// directUDPReadLoop 把来自直连远端的数据库报中继回客户端，直到 socket 失败或
// 读空闲截止时间在无数据的情况下触发。该截止时间与清理循环用于回收空闲会话的
// udpIdleTimeout 相同（用户配置超时的 2 倍），镜像服务端 UDP 处理器——它同样以
// 2 倍超时的空闲截止时间读取。退出时会关闭 socket 并从会话表中移除自己的条目，
// 但仅在条目仍指向本会话时——绝不会移除指向替换它的新会话的条目。
func (s *Socks5Server) directUDPReadLoop(relay *udpRelay, dst, key string, dc *directUDPConn) {
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
		s.sendToClient(relay, buf[:n], dst)
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
		// 非 DNS 的 UDP 不能使用较短的读空闲超时：会话可能合法地长时间沉默
		// （例如纯上传流），因此它只保留默认 60 秒的双向空闲回收器。
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

// responseDNSMsg 把一条 DNS 应答按 SOCKS5 UDP 帧写回客户端。
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
