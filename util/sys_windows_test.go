//go:build windows

package util

import (
	"net"
	"testing"
)

func TestDefaultRouteCandidates(t *testing.T) {
	// easyss TUN routes (1.0.0.0/7 … and the netsh-added 0.0.0.0/0 on the
	// TUN device) plus two physical default routes with different metrics.
	rows := []mibIpforwardrow{
		{dest: 0x01000000, mask: 0xFE000000, ifIndex: 10, metric1: 5},  // TUN 1.0.0.0/7
		{dest: 0x80000000, mask: 0x80000000, ifIndex: 10, metric1: 5},  // TUN 128.0.0.0/1
		{dest: 0x00000000, mask: 0x00000000, ifIndex: 10, metric1: 6, nextHop: 0x010214AC}, // TUN default (netsh)
		{dest: 0x00000000, mask: 0x00000000, ifIndex: 5, metric1: 35, nextHop: 0xC0A80101}, // physical default
		{dest: 0x00000000, mask: 0x00000000, ifIndex: 9, metric1: 25, nextHop: 0xC0A80101}, // physical default, lower metric
	}
	cands := defaultRouteCandidates(rows)
	if len(cands) != 3 {
		t.Fatalf("candidates = %d, want 3 (TUN + 2 physical)", len(cands))
	}
	// Sorted by metric: TUN (6), physical (25), physical (35).
	if cands[0].index != 10 || cands[0].metric != 6 {
		t.Fatalf("cands[0] = %+v, want TUN index 10 metric 6", cands[0])
	}
	if cands[1].index != 9 || cands[1].metric != 25 {
		t.Fatalf("cands[1] = %+v, want index 9 metric 25", cands[1])
	}
	if cands[2].index != 5 || cands[2].metric != 35 {
		t.Fatalf("cands[2] = %+v, want index 5 metric 35", cands[2])
	}
}

func TestDefaultRouteCandidatesNone(t *testing.T) {
	// A table with only easyss TUN routes (no 0.0.0.0/0 entry at all).
	rows := []mibIpforwardrow{
		{dest: 0x01000000, mask: 0xFE000000, ifIndex: 10, metric1: 5},
		{dest: 0x80000000, mask: 0x80000000, ifIndex: 10, metric1: 5},
	}
	if cands := defaultRouteCandidates(rows); len(cands) != 0 {
		t.Fatalf("candidates = %d, want 0", len(cands))
	}
}

func TestIPFromUint32(t *testing.T) {
	ip := ipFromUint32(0xC0A80101)
	if !ip.Equal(net.ParseIP("192.168.1.1")) {
		t.Fatalf("ipFromUint32 = %v, want 192.168.1.1", ip)
	}
}
