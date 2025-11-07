package easyss

import (
	"time"

	"github.com/nange/easyss/v2/log"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type ICMPHandler struct{}

func (ih *ICMPHandler) HandleICMPv4(id stack.TransportEndpointID, pkt *stack.PacketBuffer, s *stack.Stack) bool {
	// 只处理 Echo Request；其他类型返回 false 让栈继续走默认路径。
	icmpv4 := header.ICMPv4(pkt.TransportHeader().Slice())
	if len(icmpv4) < header.ICMPv4MinimumSize || icmpv4.Type() != header.ICMPv4Echo {
		return false
	}

	ip := header.IPv4(pkt.NetworkHeader().Slice())
	src := ip.SourceAddress()
	dst := ip.DestinationAddress()
	log.Info("[ICMPv4] Echo Request: %s -> %s ident=%d seq=%d len=%d\n",
		"src", src, "dst", dst, "ident", icmpv4.Ident(), "seq", icmpv4.Sequence(), "data_len", pkt.Data().Size())
	time.Sleep(100 * time.Millisecond)
	// 在此做你的“自定义处理逻辑”（审计/限速/黑白名单/统计等）……
	// 例如：记录或修改某些全局状态，或异步回调业务处理。
	// 这里仅打印一下：
	// log.Printf("custom handler: record flow, src=%s, dst=%s", src, dst)

	// 下面演示构造自定义 Echo Reply（会与网络层自动回复重复）：

	// 路由：localAddr 通常用我们收到的目标地址（即本机地址），遇到广播/组播场景用空地址让栈自行选本地地址。
	localAddr := dst
	if pkt.NetworkPacketInfo.LocalAddressBroadcast || header.IsV4MulticastAddress(localAddr) {
		localAddr = tcpip.Address{}
	}
	r, err := s.FindRoute(pkt.NICID, localAddr, src, header.IPv4ProtocolNumber, false /* multicastLoop */)
	if err != nil {
		// 找不到路由就放弃自定义回复。
		return true
	}
	defer r.Release()

	// 携带原始负载，回复要与请求负载一致（否则 ping 端可能不符合预期）
	replyPayload := stack.PayloadSince(pkt.TransportHeader())
	defer replyPayload.Release()

	// 准备一个包：为传输头预留 ICMPv4 头字节，为网络头预留最大长度。
	replyPkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: int(r.MaxHeaderLength()) + header.ICMPv4MinimumSize,
		Payload:            buffer.MakeWithData(replyPayload.Clone().ToSlice()),
	})
	defer replyPkt.DecRef()

	// 填写 ICMPv4 头：复制请求的头部（包含 ident/seq），把类型改为 EchoReply，重新计算校验和。
	replyICMP := header.ICMPv4(replyPkt.TransportHeader().Push(header.ICMPv4MinimumSize))
	copy(replyICMP, icmpv4[:header.ICMPv4MinimumSize]) // 拿到 ident/seq
	replyICMP.SetType(header.ICMPv4EchoReply)
	replyICMP.SetCode(header.ICMPv4UnusedCode)
	replyICMP.SetChecksum(0)
	// 校验和覆盖 ICMP 头与负载
	cs := checksum.Checksum(replyICMP, 0)
	cs = checksum.Combine(replyPkt.Data().Checksum(), cs)
	replyICMP.SetChecksum(^cs)

	// 按需自定义 TOS；也可以保留请求的 TOS。
	replyTOS, _ := ip.TOS()

	// 通过路由发送（由栈添加 IPv4 头，不包含 IP options；如需复制/更新 IP options，需改用 Header-Included 方案）
	if err := r.WritePacket(stack.NetworkHeaderParams{
		Protocol: header.ICMPv4ProtocolNumber,
		TTL:      r.DefaultTTL(),
		TOS:      replyTOS,
	}, replyPkt); err != nil {
		log.Error("custom ICMPv4 reply send failed: %v", "err", err)
	}
	return true
}

func (ih *ICMPHandler) HandleICMPv6(id stack.TransportEndpointID, pkt *stack.PacketBuffer, s *stack.Stack) bool {
	return false
}
