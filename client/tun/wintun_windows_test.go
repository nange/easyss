//go:build windows

package tun

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nange/easyss/v3/assets"
	"github.com/stretchr/testify/require"
)

// TestWriteWintunAcceptsAConcurrentExtraction 固定并发首次解压的收尾：胜者已把
// DLL 写成只读文件，败者的写入会失败，但文件完整时必须视为成功。
func TestWriteWintunAcceptsAConcurrentExtraction(t *testing.T) {
	t.Parallel()

	target := filepath.Join(t.TempDir(), "wintun.dll")
	require.NoError(t, os.WriteFile(target, assets.WintunDLL, 0o444))

	require.NoError(t, writeWintun(target))
}
