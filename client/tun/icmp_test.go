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

// Addresses used by the handler tests: a LAN gateway and a host that the
// auto rule set proxies.
var (
	lanGatewayAddr = tcpip.AddrFrom4([4]byte{192, 168, 3, 1})
	proxiedAddr    = tcpip.AddrFrom4([4]byte{8, 8, 8, 8})
)

// testPacket is the adapter.Packet the tun2socks ICMP forwarder hands to the
// handler: a packet buffer plus the transport endpoint ID the handler reads
// the destination address from.
type testPacket struct {
	pkt *stack.PacketBuffer
	id  stack.TransportEndpointID
}

func (p *testPacket) Buffer() *stack.PacketBuffer { return p.pkt }

func (p *testPacket) Stack() *stack.Stack { return nil }

func (p *testPacket) ID() stack.TransportEndpointID { return p.id }

// newPacket builds a packet whose network header is netHdrLen bytes followed
// by icmpMsg, in the order the stack parses an inbound packet. The header
// contents do not matter: only the ICMP type byte is read.
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

// icmpv4Msg and icmpv6Msg build a minimal ICMP message of the given type.
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
	// A packet too short to hold an ICMP header (a truncated capture) must be
	// reported as non-echo instead of panicking.
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

// TestHandlePacketLogsOnlyEchoRequests is the regression test for the INFO
// flood this handler used to produce: a LAN gateway probes every host on its
// network, the kernel replies to each probe, and once the gateway address is
// routed into the TUN device those replies (ICMP type 0) arrive here. Logging
// them at INFO produced several lines per second forever, so only echo
// requests — the messages that actually carry a routing decision — may reach
// the INFO log; every other type belongs to the debug log.
func TestHandlePacketLogsOnlyEchoRequests(t *testing.T) {
	// Build the router before swapping the logger: router.New logs the rule
	// files it loads and that output is not part of what this test asserts.
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

			// No proxied exchange can complete in this test, so every case
			// ends with the packet left to the default forwarder.
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

// recordingHandler captures every record the log package emits so tests can
// assert which levels a code path logs at.
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

// infoMessages returns the messages of every record logged at INFO or above.
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

// messages renders "level message" for every record, for failure output.
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
