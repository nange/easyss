//go:build windows

package tun

import (
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestEnsureWintunConcurrentCallsSucceed 固定并发首次解压的最终状态：所有调用都成功，
// 且留下完整文件。它不区分是谁写的，因此只是行为冒烟，不证明单写者。
func TestEnsureWintunConcurrentCallsSucceed(t *testing.T) {
	t.Parallel()

	target := filepath.Join(t.TempDir(), "wintun.dll")
	errs := make(chan error, 8)
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() { errs <- ensureWintunAt(target) })
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		require.NoError(t, err)
	}
	require.True(t, wintunReady(target))
}

// TestEnsureWintunReplacesAnIncompleteFile 固定判据一致：截断的旧文件既不算就绪，
// 也必须能被覆盖（只读属性要先清掉）。
func TestEnsureWintunReplacesAnIncompleteFile(t *testing.T) {
	t.Parallel()

	target := filepath.Join(t.TempDir(), "wintun.dll")
	require.NoError(t, os.WriteFile(target, []byte("x"), 0o444))

	require.NoError(t, ensureWintunAt(target))
	require.True(t, wintunReady(target))
}
