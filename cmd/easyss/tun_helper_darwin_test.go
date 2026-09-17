//go:build darwin

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nange/easyss/v3/scripts"
	"github.com/stretchr/testify/require"
)

// TestRunCreateScriptStripsV6Prefix 固定 helper 路径上的实参契约：
// runCreateScript 交给 create_tun_dev_darwin.sh 的 IPv6 地址必须是裸地址。
//
// 脚本自己把 "/64" 拼到 ifconfig 的 inet6 参数上，而 TunIPV6Sub 来自
// client/tun 的默认值 "2001:0db8:0:f101::1/64"（linux 脚本的
// "ip -6 addr replace" 需要 CIDR 形式），直接透传会拼出 ".../64/64"。
// ifconfig 报 "bad value" 并以退出码 1 结束，helper 于是对托盘报告
// "run create script" 失败，TUN 完全起不来——正是这个测试要拦住的回归。
//
// 真实的创建脚本需要 root 而且会重配运行测试的机器的网络，因此这里把内嵌
// 脚本替换成记录自身实参的脚本：本测试要证明的是传给脚本的参数，
// 而不是脚本本身（脚本由 tun_script_unix_test.go 覆盖）。
func TestRunCreateScriptStripsV6Prefix(t *testing.T) {
	origBytes, origName := scripts.CreateTunBytes, scripts.CreateTunFilename
	t.Cleanup(func() { scripts.CreateTunBytes, scripts.CreateTunFilename = origBytes, origName })

	marker := filepath.Join(t.TempDir(), "create-args")
	scripts.CreateTunFilename = "create_tun_dev_darwin_args_test.sh"
	scripts.CreateTunBytes = []byte("#!/bin/sh\nprintf '%s\\n' \"$@\" > \"" + marker + "\"\n")

	require.NoError(t, runCreateScript("utun9", "198.18.0.1", "198.18.0.1", "192.168.3.1",
		"2001:0db8:0:f101::1/64", "fe80::1", "2001:db8::2", "fe80::2"))

	data, err := os.ReadFile(marker)
	require.NoError(t, err, "the create script did not run")

	got := strings.Split(strings.TrimSpace(string(data)), "\n")
	require.Equal(t, []string{
		"utun9", "198.18.0.1", "198.18.0.1", "192.168.3.1",
		"2001:0db8:0:f101::1", "fe80::1", "2001:db8::2", "fe80::2",
	}, got, "the script appends the prefix itself, so the address must arrive bare")
}

// TestBareV6Addr 覆盖 helper 侧的去前缀辅助函数：带前缀的输入去掉前缀，
// 不带前缀的输入原样返回（TunIPV6Sub 也可能已经是裸地址）。
func TestBareV6Addr(t *testing.T) {
	require.Equal(t, "2001:db8::1", bareV6Addr("2001:db8::1/64"))
	require.Equal(t, "2001:db8::1", bareV6Addr("2001:db8::1"))
	require.Equal(t, "", bareV6Addr(""))
}
