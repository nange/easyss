//go:build windows && !headless

package autostart

import (
	"strings"
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

// TestRunExeTakesTheQuotedPath 固定解析口径：值里可能有旧版本留下的裸路径或用户追加的参数，
// 只有可执行文件路径本身参与比较。
func TestRunExeTakesTheQuotedPath(t *testing.T) {
	t.Parallel()

	require.Equal(t, `C:\Program Files\Easyss\easyss.exe`, runExe(`"C:\Program Files\Easyss\easyss.exe" -minimized`))
	require.Equal(t, `C:\easyss\easyss.exe`, runExe(`C:\easyss\easyss.exe`))
	require.Equal(t, `C:\easyss\easyss.exe`, runExe("  \"C:\\easyss\\easyss.exe\"  "))
}

// TestSameExecutableIgnoresExtensionAndCase：`make easyss` 的 bin/easyss 没有扩展名，
// 直接运行时写进 Run 的路径也不带 .exe，此后跑的 easyss.exe 必须仍被视为"已启用"。
func TestSameExecutableIgnoresExtensionAndCase(t *testing.T) {
	t.Parallel()

	exe := `C:\Users\Administrator\go\src\github.com\nange\easyss\bin\easyss.exe`
	dir := `C:\Users\Administrator\go\src\github.com\nange\easyss\bin`

	require.True(t, sameExecutable(runValue(exe), exe))
	require.True(t, sameExecutable(`"`+strings.ToUpper(exe)+`"`, exe))
	require.True(t, sameExecutable(dir+`\easyss`, exe))
	require.True(t, sameExecutable(runValue(exe), dir+`\easyss`))
	require.False(t, sameExecutable(`"`+dir+`\easyss-server.exe"`, exe))
	require.False(t, sameExecutable(`"C:\easyss\easyss.exe"`, exe))
}
