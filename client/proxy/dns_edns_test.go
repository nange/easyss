package proxy

import (
	"testing"

	"github.com/miekg/dns"
	"github.com/nange/easyss/v3/protocol"
)

// TestClampDNSEDNS0 固定"经隧道的 DNS 查询不会向上游宣告超过隧道读缓冲的
// 接收尺寸"：否则上游会合法地发出一个超过 16,362 字节的应答，被服务端的
// 截断检测丢弃，查询表现为超时。
func TestClampDNSEDNS0(t *testing.T) {
	query := func(edns uint16, withOPT bool) *dns.Msg {
		msg := new(dns.Msg)
		msg.SetQuestion("example.com.", dns.TypeA)
		if withOPT {
			msg.SetEdns0(edns, false)
		}
		return msg
	}

	tooLarge := query(65535, true)
	if !clampDNSEDNS0(tooLarge) {
		t.Fatal("EDNS0 尺寸大于隧道预算时必须改写")
	}
	opt := tooLarge.IsEdns0()
	if opt == nil {
		t.Fatal("改写后 OPT 记录不应消失")
	}
	if got := opt.UDPSize(); got != uint16(protocol.MaxUDPDataSize) {
		t.Fatalf("EDNS0 UDPSize = %d, want %d", got, protocol.MaxUDPDataSize)
	}
	if clampDNSEDNS0(tooLarge) {
		t.Fatal("已经等于预算的查询不应再次改写")
	}
	if _, err := tooLarge.Pack(); err != nil {
		t.Fatalf("改写后的查询必须仍可打包: %v", err)
	}

	exact := query(uint16(protocol.MaxUDPDataSize), true)
	if clampDNSEDNS0(exact) {
		t.Fatal("恰好等于预算的 EDNS0 不应改写")
	}
	small := query(4096, true)
	if clampDNSEDNS0(small) {
		t.Fatal("小于预算的 EDNS0 不应改写")
	}
	noOPT := query(0, false)
	if clampDNSEDNS0(noOPT) {
		t.Fatal("没有 OPT 的查询不应改写")
	}
}
