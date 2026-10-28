//go:build !headless && windows

package app

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestRestartArgsQuotesTheConfigPath 固定提权重启的参数拼装：配置路径在用户目录里常带空格，
// 裸拼会被拆成多个参数，新进程读不到配置就会以默认值启动——看起来"重启了"，实际是另一个实例。
func TestRestartArgsQuotesTheConfigPath(t *testing.T) {
	require.Equal(t, "-enable-tun2socks -elevated-restart", restartArgs(""))
	require.Equal(t,
		`-c "C:\Users\some one\Easyss\config.json" -enable-tun2socks -elevated-restart`,
		restartArgs(`C:\Users\some one\Easyss\config.json`),
		"配置路径必须整体加引号")
}
