//go:build windows

package tun

import (
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestEnsureWintunSerializesConcurrentExtraction 钉住进程内并发首次解压：并行测试
// 同时 Start 时只有一个 goroutine 写文件，其余在锁内看到完整文件后直接返回。
func TestEnsureWintunSerializesConcurrentExtraction(t *testing.T) {
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
