package dns

import (
	"errors"
	"testing"
	"time"
)

// resetSystemDNSCache clears the cached system dns servers so that a test
// injected sysDNSFunc result does not leak into other tests.
func resetSystemDNSCache() {
	systemDNSMu.Lock()
	systemDNSCached = nil
	systemDNSTime = time.Time{}
	systemDNSMu.Unlock()
}

func TestSystemDNSServers(t *testing.T) {
	calls := 0
	old := sysDNSFunc
	sysDNSFunc = func() ([]string, error) {
		calls++
		return []string{"192.168.1.1", "2400:3200::1"}, nil
	}
	t.Cleanup(func() {
		sysDNSFunc = old
		resetSystemDNSCache()
	})

	got := SystemDNSServers()
	want := []string{"192.168.1.1:53", "[2400:3200::1]:53"}
	if len(got) != len(want) {
		t.Fatalf("expected %v, got %v", want, got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("expected %v, got %v", want, got)
		}
	}

	// the result is cached: a second call must not re-discover
	SystemDNSServers()
	if calls != 1 {
		t.Fatalf("expected 1 discovery call, got %d", calls)
	}
}

func TestSystemDNSServersError(t *testing.T) {
	old := sysDNSFunc
	sysDNSFunc = func() ([]string, error) {
		return nil, errors.New("discovery failed")
	}
	t.Cleanup(func() {
		sysDNSFunc = old
		resetSystemDNSCache()
	})

	if got := SystemDNSServers(); got != nil {
		t.Fatalf("expected nil, got %v", got)
	}
}
