package proxy

import "testing"

// TestRemoveExchangeKeepsReplacement 固定"过期的 receiveLoop 收尾不得删掉
// 新交换"：驱逐/空闲清理摘除旧交换后，同一 key 可能已经登记了替代者；旧
// receiveLoop 的 defer 若无条件 delete，会把替代者从池里抹掉，留下一个无人
// 回收的交换（非 DNS 的 UDP 交换没有读空闲定时器）。
func TestRemoveExchangeKeepsReplacement(t *testing.T) {
	p := newUDPPool(udpPoolOptions{})

	oldStream := newBlockingStream()
	old := &UDPExchange{stream: oldStream}
	replacementStream := newBlockingStream()
	replacement := &UDPExchange{stream: replacementStream}

	p.exchanges["client_target"] = replacement
	p.removeExchange("client_target", old)

	if got := p.exchanges["client_target"]; got != replacement {
		t.Fatalf("replacement exchange was removed from the pool: got %p, want %p", got, replacement)
	}
	if !oldStream.isClosed() {
		t.Fatal("the removed exchange must still be closed")
	}
	if replacementStream.isClosed() {
		t.Fatal("the replacement exchange must not be closed")
	}
}

// TestAddUDPRelayRefusesAfterClose 固定“Close 扫描过表之后不再接受新中继”：
// 否则在扫描与登记之间插入的 socket 不会被任何一方关闭。
func TestAddUDPRelayRefusesAfterClose(t *testing.T) {
	s := &Socks5Server{}
	s.closeUDPRelays()

	if s.addUDPRelay(&udpRelay{}) {
		t.Fatal("relay registration must be refused after the server is closed")
	}
}

// TestRemoveExchangeDeletesOwnEntry 覆盖正常收尾：条目仍指向本交换时删除。
func TestRemoveExchangeDeletesOwnEntry(t *testing.T) {
	p := newUDPPool(udpPoolOptions{})
	stream := newBlockingStream()
	ue := &UDPExchange{stream: stream}
	p.exchanges["client_target"] = ue

	p.removeExchange("client_target", ue)

	if _, ok := p.exchanges["client_target"]; ok {
		t.Fatal("the owning exchange should be removed from the pool")
	}
	if !stream.isClosed() {
		t.Fatal("the removed exchange must be closed")
	}
}
