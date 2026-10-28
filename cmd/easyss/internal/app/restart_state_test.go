package app

import (
	"flag"
	"testing"

	clientconfig "github.com/nange/easyss/v3/client/config"
	"github.com/stretchr/testify/require"
)

// TestRestartStateRoundTrip 固定线格式：encode 与 Set 必须互逆，字段顺序由 encode 决定。
func TestRestartStateRoundTrip(t *testing.T) {
	var st RestartState
	require.NoError(t, st.Set("server=3,sysproxy=on,rule=direct,log=warn"))
	require.True(t, st.Enabled())
	require.Equal(t, "server=3,sysproxy=on,rule=direct,log=warn", st.encode())
}

// TestRestartStatePresenceMeansRestart 守住最危险的退化：空载荷和裸 flag 仍然要重启，
// 否则新实例会按普通启动去抢互斥量、失败后静默退出——用户过完 UAC 两个实例都没了。
func TestRestartStatePresenceMeansRestart(t *testing.T) {
	for _, v := range []string{"", "true"} {
		var st RestartState
		require.NoError(t, st.Set(v))
		require.True(t, st.Enabled(), "value %q", v)
		require.Empty(t, st.encode(), "空载荷不得写出 fake key")
	}

	var off RestartState
	require.NoError(t, off.Set("false"))
	require.False(t, off.Enabled())
	require.Equal(t, "false", off.String())
}

// TestRestartStateIgnoresBrokenPayload 固定容错：坏 key/坏值只丢该项，绝不阻断启动——
// 这条 flag 出现在 UAC 授权之后，flag.Parse 报错就再也拉不起界面了。
func TestRestartStateIgnoresBrokenPayload(t *testing.T) {
	var st RestartState
	require.NoError(t, st.Set("server=x,sysproxy=maybe,bogus=1,=,rule"))
	require.True(t, st.Enabled())
	require.Empty(t, st.encode())
}

// TestRestartStateAsFlag 固定两种写法：裸写（IsBoolFlag）合法，载荷必须用等号形式——
// flag 遇到第一个非 flag 参数就停止解析，空格形式会把载荷静默丢给位置参数。
func TestRestartStateAsFlag(t *testing.T) {
	var bare RestartState
	fs := flag.NewFlagSet("restart", flag.ContinueOnError)
	fs.Var(&bare, "elevated-restart", "")
	require.NoError(t, fs.Parse([]string{"-elevated-restart"}))
	require.True(t, bare.Enabled())
	require.Empty(t, bare.encode())

	var payload RestartState
	fs = flag.NewFlagSet("restart", flag.ContinueOnError)
	fs.Var(&payload, "elevated-restart", "")
	require.NoError(t, fs.Parse([]string{"-elevated-restart=server=1,sysproxy=on"}))
	require.Equal(t, "server=1,sysproxy=on", payload.encode())

	var spaced RestartState
	fs = flag.NewFlagSet("restart", flag.ContinueOnError)
	fs.Var(&spaced, "elevated-restart", "")
	require.NoError(t, fs.Parse([]string{"-elevated-restart", "server=1"}))
	require.True(t, spaced.Enabled())
	require.Empty(t, spaced.encode(), "空格形式会丢载荷，restartArgs 必须只用等号形式")
}

// TestRestartStateApply 固定写回语义：只覆盖载荷里出现的项；服务器下标越界（UAC 期间
// 用户改了配置文件）时保留文件里的默认服务器；没带 flag 时是空操作。
func TestRestartStateApply(t *testing.T) {
	cfg := &clientconfig.ClientConfig{Servers: []*clientconfig.ServerProfile{{Host: "a"}, {Host: "b"}}}
	cfg.SetDefaultServerIndex(0)
	cfg.Routing.ProxyRule = "auto"
	cfg.Log.Level = "info"

	var st RestartState
	require.NoError(t, st.Set("server=1,sysproxy=on,rule=direct,log=debug"))
	st.Apply(cfg)
	require.True(t, cfg.Servers[1].Default, "服务器选择必须跟着交接过来")
	require.False(t, cfg.Local.DisableSysProxy)
	require.Equal(t, "direct", cfg.Routing.ProxyRule)
	require.Equal(t, "debug", cfg.Log.Level)

	var outOfRange RestartState
	require.NoError(t, outOfRange.Set("server=9"))
	outOfRange.Apply(cfg)
	require.True(t, cfg.Servers[1].Default, "越界下标必须保留配置文件里的默认服务器")

	var partial RestartState
	require.NoError(t, partial.Set("sysproxy=off"))
	partial.Apply(cfg)
	require.True(t, cfg.Local.DisableSysProxy)
	require.Equal(t, "debug", cfg.Log.Level, "载荷里没有的项不得改动配置")

	var none RestartState
	require.NoError(t, none.Set("false"))
	none.Apply(cfg)
	require.True(t, cfg.Local.DisableSysProxy, "没带这个 flag 时必须是空操作")
	require.True(t, cfg.Servers[1].Default)
}
