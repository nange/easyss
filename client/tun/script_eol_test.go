package tun

import (
	"bytes"
	"os"
	"testing"

	"github.com/nange/easyss/v3/client/tun/scripts"
	"github.com/stretchr/testify/require"
)

// TestNormalizeScriptEOL 钉住落盘前统一 .bat 行尾：cmd.exe 在中文 Windows（OEM 936）上执行
// LF 批处理会把多字节注释与换行错位、注释被当成命令执行，而 go:embed 取的是工作区原始字节。
func TestNormalizeScriptEOL(t *testing.T) {
	t.Parallel()

	t.Run("批处理脚本统一成 CRLF", func(t *testing.T) {
		got := normalizeScriptEOL("create_tun_dev_windows.bat", []byte("@echo off\nrem 中文注释\n"))
		require.Equal(t, "@echo off\r\nrem 中文注释\r\n", string(got))
	})

	t.Run("已经是 CRLF 时幂等", func(t *testing.T) {
		in := []byte("@echo off\r\nrem 中文注释\r\n")
		require.Equal(t, string(in), string(normalizeScriptEOL("create_tun_dev_windows.bat", in)))
	})

	t.Run("混合行尾也要归一", func(t *testing.T) {
		got := normalizeScriptEOL("x.bat", []byte("a\nb\r\nc"))
		require.Equal(t, "a\r\nb\r\nc", string(got))
		require.NotContains(t, string(got), "\r\r")
	})

	// shell 脚本带 CRLF 会让 bash 报 "\r: command not found"，所以只能原样落盘。
	t.Run("shell 脚本与其他文件原样返回", func(t *testing.T) {
		in := []byte("#!/bin/sh\necho hi\n")
		require.Equal(t, string(in), string(normalizeScriptEOL("create_tun_dev.sh", in)))
		require.Equal(t, string(in), string(normalizeScriptEOL("create_tun_dev_darwin.sh", in)))
		require.Equal(t, string(in), string(normalizeScriptEOL("no-extension", in)))
	})

	t.Run("空输入", func(t *testing.T) {
		require.Empty(t, normalizeScriptEOL("x.bat", nil))
	})

	// 落盘的那一份才是 cmd.exe / sh 读的东西（Windows 上随后还会被改名成脚本本名），
	// 所以这里直接核对磁盘上的字节。
	t.Run("落盘的是 CRLF 字节", func(t *testing.T) {
		path, err := WriteScriptToTemp("create_tun_dev_windows.bat", []byte("@echo off\nrem 中文注释\n"))
		require.NoError(t, err)
		t.Cleanup(func() { _ = os.Remove(path) })

		onDisk, err := os.ReadFile(path)
		require.NoError(t, err)
		require.Equal(t, "@echo off\r\nrem 中文注释\r\n", string(onDisk),
			"cmd.exe reads what is on disk: LF input must be written back as CRLF")

		shPath, err := WriteScriptToTemp("create_tun_dev.sh", []byte("#!/bin/sh\necho hi\n"))
		require.NoError(t, err)
		t.Cleanup(func() { _ = os.Remove(shPath) })

		shOnDisk, err := os.ReadFile(shPath)
		require.NoError(t, err)
		require.Equal(t, "#!/bin/sh\necho hi\n", string(shOnDisk),
			"a CRLF shell script makes bash fail with \"\\r: command not found\"")
	})

	// 无论工作区是哪种行尾，embed 进二进制的 Windows 脚本落盘执行时都是 CRLF。
	t.Run("embed 的 Windows 脚本落盘即 CRLF", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			data []byte
		}{
			{scripts.CreateTunFilename, scripts.CreateTunDevBat},
			{scripts.CloseTunFilename, scripts.CloseTunDevBat},
		} {
			require.NotEmpty(t, tc.data, "%s must be embedded", tc.name)

			out := normalizeScriptEOL(tc.name, tc.data)
			require.Equal(t, bytes.Count(out, []byte("\n")), bytes.Count(out, []byte("\r\n")),
				"%s: every LF must be part of a CRLF", tc.name)
			require.NotContains(t, string(out), "\r\r", "%s", tc.name)
		}
	})
}
