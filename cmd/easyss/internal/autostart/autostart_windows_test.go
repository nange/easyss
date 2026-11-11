//go:build windows && !headless

package autostart

import (
	"os"
	"path/filepath"
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

// TestCanonicalRunExePrefersTheExistingExe 固定改写目标：只有同名 .exe 不存在时才原样
// 保留无扩展名路径，否则 Run 值会退化成依赖 ShellExecute 按 PATHEXT 解析的形态。
func TestCanonicalRunExePrefersTheExistingExe(t *testing.T) {
	t.Parallel()

	noExt := filepath.Join(t.TempDir(), "easyss")
	require.Equal(t, noExt, canonicalRunExe(noExt))

	require.NoError(t, os.WriteFile(noExt+".exe", nil, 0o600))
	require.Equal(t, noExt+".exe", canonicalRunExe(noExt))
	require.Equal(t, noExt+".exe", canonicalRunExe(noExt+".exe"))
}

// TestSameExecutableIgnoresExtensionAndCase：`make easyss` 的 bin/easyss 没有扩展名，
// 写进 Run 的路径也不带 .exe，此后跑的 easyss.exe 必须仍被视为"已启用"。
func TestSameExecutableIgnoresExtensionAndCase(t *testing.T) {
	t.Parallel()

	exe := filepath.Join(t.TempDir(), "easyss.exe")
	require.NoError(t, os.WriteFile(exe, nil, 0o600))
	noExt := strings.TrimSuffix(exe, ".exe")

	require.True(t, sameExecutable(runValue(exe), exe))
	require.True(t, sameExecutable(`"`+strings.ToUpper(exe)+`"`, exe))
	require.True(t, sameExecutable(runValue(noExt), exe))
	require.True(t, sameExecutable(runValue(exe), noExt))
	require.False(t, sameExecutable(runValue(filepath.Join(filepath.Dir(exe), "easyss-server.exe")), exe))
	require.False(t, sameExecutable(`"C:\easyss\easyss.exe"`, exe))
}

// TestIsBarePathValueKeepsUserArguments 固定"带参数的值只比较不改写"，否则用户手加的
// -c 之类的参数会被静默丢掉。
func TestIsBarePathValueKeepsUserArguments(t *testing.T) {
	t.Parallel()

	require.True(t, isBarePathValue(runValue(`C:\easyss\easyss.exe`)))
	require.True(t, isBarePathValue("  "+runValue(`C:\easyss\easyss.exe`)+"  "))
	require.False(t, isBarePathValue(`"C:\easyss\easyss.exe" -c "D:\cfg.json"`))
	require.False(t, isBarePathValue(`C:\easyss\easyss.exe`))
}
