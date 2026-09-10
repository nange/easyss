package mobile

import (
	"strings"
	"testing"

	"github.com/nange/easyss/v3/runner"
)

// withCore swaps the package-level Core under the same lock the binding uses,
// restoring the previous value when the test ends.
func withCore(t *testing.T, core *runner.Core) {
	t.Helper()

	mMu.Lock()
	prev := mCore
	mCore = core
	mMu.Unlock()

	t.Cleanup(func() {
		mMu.Lock()
		mCore = prev
		mMu.Unlock()
	})
}

// TestWarmUpWithoutStart verifies that calling the binding before Start is
// reported to the caller instead of being silently ignored.
func TestWarmUpWithoutStart(t *testing.T) {
	withCore(t, nil)

	err := WarmUp()

	if err == nil {
		t.Fatal("expected an error when the core is not started, got nil")
	}
	if !strings.Contains(err.Error(), "not started") {
		t.Errorf("error = %v, want it to mention that Start must be called first", err)
	}
}

// TestWarmUpWithoutSocksServer verifies the skip path: a core without a local
// SOCKS5 proxy has nothing to warm, which is not a failure and must not block.
func TestWarmUpWithoutSocksServer(t *testing.T) {
	withCore(t, &runner.Core{})

	if err := WarmUp(); err != nil {
		t.Errorf("expected nil when there is no SOCKS5 server, got %v", err)
	}
}
