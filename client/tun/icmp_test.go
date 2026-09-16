package tun

import (
	"context"
	"log/slog"
	"slices"
	"strconv"
	"sync"
	"testing"

	"github.com/nange/easyss/v3/client/router"
	"github.com/nange/easyss/v3/log"
	"github.com/xjasonlyu/tun2socks/v2/core/adapter"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// handler 测试用到的地址：一个局域网网关，以及一个被 auto 规则集代理的主机。
var (
	lanGatewayAddr = tcpip.AddrFrom4([4]byte{192, 168, 3, 1})
	proxiedAddr    = tcpip.AddrFrom4([4]byte{8, 8, 8, 8})
)

// testPacket 是 tun2socks 的 ICMP forwarder 交给 handler 的 adapter.Packet：
// 一个报文缓冲区，加上 handler 用来读取目的地址的传输端点 ID。
type testPacket struct {
	pkt *stack.PacketBuffer
	id  stack.TransportEndpointID
}

func (p *testPacket) Buffer() *stack.PacketBuffer { return p.pkt }

func (p *testPacket) Stack() *stack.Stack { return nil }

func (p *testPacket) ID() stack.TransportEndpointID { return p.id }

// newPacket 构造一个报文：网络头为 netHdrLen 字节，其后紧跟 icmpMsg，顺序与
// stack 解析入站报文时一致。头部内容无关紧要：只有 ICMP 类型字节会被读取。
func newPacket(t *testing.T, netProto tcpip.NetworkProtocolNumber, netHdrLen int, icmpMsg []byte) *testPacket {
	t.Helper()

	raw := make([]byte, netHdrLen+len(icmpMsg))
	copy(raw[netHdrLen:], icmpMsg)

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(raw)})
	t.Cleanup(pkt.DecRef)
	pkt.NetworkProtocolNumber = netProto

	if _, ok := pkt.NetworkHeader().Consume(netHdrLen); !ok {
		t.Fatalf("consume %d-byte network header of a %d-byte packet", netHdrLen, len(raw))
	}
	if _, ok := pkt.TransportHeader().Consume(len(icmpMsg)); !ok {
		t.Fatalf("consume %d-byte ICMP message", len(icmpMsg))
	}
	return &testPacket{pkt: pkt}
}

// icmpv4Msg 和 icmpv6Msg 构造一个给定类型的最小 ICMP 报文。
func icmpv4Msg(typ header.ICMPv4Type) []byte {
	msg := make([]byte, header.ICMPv4MinimumSize)
	header.ICMPv4(msg).SetType(typ)
	return msg
}

func icmpv6Msg(typ header.ICMPv6Type) []byte {
	msg := make([]byte, header.ICMPv6MinimumSize)
	header.ICMPv6(msg).SetType(typ)
	return msg
}

func TestICMPEchoRequest(t *testing.T) {
	cases := []struct {
		name      string
		netProto  tcpip.NetworkProtocolNumber
		netHdrLen int
		icmpMsg   []byte
		wantType  uint8
		wantEcho  bool
	}{
		{"ipv4 echo request", ipv4.ProtocolNumber, header.IPv4MinimumSize,
			icmpv4Msg(header.ICMPv4Echo), uint8(header.ICMPv4Echo), true},
		{"ipv4 echo reply", ipv4.ProtocolNumber, header.IPv4MinimumSize,
			icmpv4Msg(header.ICMPv4EchoReply), uint8(header.ICMPv4EchoReply), false},
		{"ipv4 destination unreachable", ipv4.ProtocolNumber, header.IPv4MinimumSize,
			icmpv4Msg(header.ICMPv4DstUnreachable), uint8(header.ICMPv4DstUnreachable), false},
		{"ipv6 echo request", header.IPv6ProtocolNumber, header.IPv6MinimumSize,
			icmpv6Msg(header.ICMPv6EchoRequest), uint8(header.ICMPv6EchoRequest), true},
		{"ipv6 echo reply", header.IPv6ProtocolNumber, header.IPv6MinimumSize,
			icmpv6Msg(header.ICMPv6EchoReply), uint8(header.ICMPv6EchoReply), false},
		{"ipv6 neighbour solicitation", header.IPv6ProtocolNumber, header.IPv6MinimumSize,
			icmpv6Msg(header.ICMPv6NeighborSolicit), uint8(header.ICMPv6NeighborSolicit), false},
		{"unknown network protocol", 99, header.IPv4MinimumSize,
			icmpv4Msg(header.ICMPv4Echo), 0, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotType, gotEcho := icmpEchoRequest(newPacket(t, tc.netProto, tc.netHdrLen, tc.icmpMsg))
			if gotEcho != tc.wantEcho || gotType != tc.wantType {
				t.Errorf("icmpEchoRequest() = (%d, %v), want (%d, %v)",
					gotType, gotEcho, tc.wantType, tc.wantEcho)
			}
		})
	}
}

func TestICMPEchoRequestMalformed(t *testing.T) {
	// 短到装不下 ICMP 头的报文（截断的抓包）必须被报告为非 echo，而不是 panic。
	t.Run("empty transport header", func(t *testing.T) {
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithData([]byte{0x45, 0x00, 0x00, 0x00}),
		})
		t.Cleanup(pkt.DecRef)
		pkt.NetworkProtocolNumber = ipv4.ProtocolNumber

		if typ, ok := icmpEchoRequest(&testPacket{pkt: pkt}); ok || typ != 0 {
			t.Errorf("icmpEchoRequest() = (%d, %v), want (0, false)", typ, ok)
		}
	})

	t.Run("nil buffer", func(t *testing.T) {
		if typ, ok := icmpEchoRequest(&testPacket{}); ok || typ != 0 {
			t.Errorf("icmpEchoRequest() = (%d, %v), want (0, false)", typ, ok)
		}
	})
}

// TestHandlePacketLogsOnlyEchoRequests 是针对本 handler 曾经产生的 INFO 日志
// 洪泛的回归测试：局域网网关会探测其网络上的每台主机，内核回复每个探测，而一旦
// 网关地址被路由进 TUN 设备，这些回复（ICMP 类型 0）就会到达这里。把它们记成
// INFO 日志会永久性地每秒产生数行输出，因此只有 echo 请求——真正携带路由决策
// 的报文——才能进入 INFO 日志；其他所有类型都归调试日志。
func TestHandlePacketLogsOnlyEchoRequests(t *testing.T) {
	// 在替换 logger 之前先构建 router：router.New 会记录它加载的规则文件，
	// 而那段输出不在本测试的断言范围内。
	rt, err := router.New(router.Config{ProxyRule: router.ProxyRuleAuto})
	if err != nil {
		t.Fatalf("router.New: %v", err)
	}

	rec := &recordingHandler{}
	prev := log.Logger()
	log.SetLogger(slog.New(rec))
	t.Cleanup(func() { log.SetLogger(prev) })

	h := NewICMPHandler(rt)

	cases := []struct {
		name     string
		typ      header.ICMPv4Type
		dst      tcpip.Address
		wantInfo []string
	}{
		{
			name:     "echo request to the lan gateway",
			typ:      header.ICMPv4Echo,
			dst:      lanGatewayAddr,
			wantInfo: []string{"[ICMP_DIRECT]"},
		},
		{
			name:     "echo request to a proxied host",
			typ:      header.ICMPv4Echo,
			dst:      proxiedAddr,
			wantInfo: []string{"[ICMP_PROXY]"},
		},
		{
			name:     "echo reply from the lan gateway",
			typ:      header.ICMPv4EchoReply,
			dst:      lanGatewayAddr,
			wantInfo: nil,
		},
		{
			name:     "destination unreachable from the lan gateway",
			typ:      header.ICMPv4DstUnreachable,
			dst:      lanGatewayAddr,
			wantInfo: nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec.reset()

			pkt := newPacket(t, ipv4.ProtocolNumber, header.IPv4MinimumSize, icmpv4Msg(tc.typ))
			pkt.id = stack.TransportEndpointID{LocalAddress: tc.dst}

			// 本测试中不会有任何代理交换完成，所以每个用例最终都把报文
			// 留给默认 forwarder 处理。
			if got := h.HandlePacket(pkt); got {
				t.Errorf("HandlePacket() = true, want false")
			}

			if infos := rec.infoMessages(); !slices.Equal(infos, tc.wantInfo) {
				t.Errorf("INFO logs = %v, want %v (all levels: %v)", infos, tc.wantInfo, rec.messages())
			}

			if len(tc.wantInfo) == 0 {
				if !rec.hasMessage("[ICMP_DROP]") {
					t.Errorf("non-echo packet logged no [ICMP_DROP] record: %v", rec.messages())
				}
				return
			}

			r, ok := rec.findRecord(slog.LevelInfo, tc.wantInfo[0])
			if !ok {
				t.Fatalf("no INFO record %q", tc.wantInfo[0])
			}
			got, ok := attrValue(r, "type")
			if !ok {
				t.Fatalf("record %q has no type attribute", tc.wantInfo[0])
			}
			if want := strconv.Itoa(int(tc.typ)); got.String() != want {
				t.Errorf("type attribute = %q, want %q", got.String(), want)
			}
		})
	}
}

// recordingHandler 捕获 log 包发出的每一条记录，使测试可以断言某条代码路径
// 在哪些级别上记录日志。
type recordingHandler struct {
	mu      sync.Mutex
	records []slog.Record
}

func (h *recordingHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *recordingHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, r.Clone())
	return nil
}

func (h *recordingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }

func (h *recordingHandler) WithGroup(string) slog.Handler { return h }

func (h *recordingHandler) reset() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = nil
}

// infoMessages 返回所有在 INFO 及以上级别记录的日志消息。
func (h *recordingHandler) infoMessages() []string {
	h.mu.Lock()
	defer h.mu.Unlock()

	var msgs []string
	for _, r := range h.records {
		if r.Level >= slog.LevelInfo {
			msgs = append(msgs, r.Message)
		}
	}
	return msgs
}

func (h *recordingHandler) hasMessage(msg string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()

	return slices.ContainsFunc(h.records, func(r slog.Record) bool { return r.Message == msg })
}

func (h *recordingHandler) findRecord(level slog.Level, msg string) (slog.Record, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()

	for _, r := range h.records {
		if r.Level == level && r.Message == msg {
			return r, true
		}
	}
	return slog.Record{}, false
}

// messages 将每条记录渲染为 "level message" 形式，用于失败输出。
func (h *recordingHandler) messages() []string {
	h.mu.Lock()
	defer h.mu.Unlock()

	msgs := make([]string, 0, len(h.records))
	for _, r := range h.records {
		msgs = append(msgs, r.Level.String()+" "+r.Message)
	}
	return msgs
}

func attrValue(r slog.Record, key string) (slog.Value, bool) {
	var (
		val   slog.Value
		found bool
	)
	r.Attrs(func(a slog.Attr) bool {
		if a.Key == key {
			val, found = a.Value, true
			return false
		}
		return true
	})
	return val, found
}

var _ adapter.Packet = (*testPacket)(nil)
