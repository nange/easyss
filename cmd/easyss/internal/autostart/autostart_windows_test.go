//go:build windows && !headless

package autostart

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestRunValueQuotesTheExecutablePath 固定 Run 键的写法：不加引号的带空格路径交给
// ShellExecute 解析时会先尝试 "C:\Program.exe" 之类的中间名，可能启动别的程序。
// isAutoStartEnabled 用同一个函数写入的值比对，因此改动必须两侧同源。
func TestRunValueQuotesTheExecutablePath(t *testing.T) {
	require.Equal(t, `"C:\Program Files\Easyss\easyss.exe"`, runValue(`C:\Program Files\Easyss\easyss.exe`))
	require.Equal(t, `"C:\easyss\easyss.exe"`, runValue(`C:\easyss\easyss.exe`))
}
