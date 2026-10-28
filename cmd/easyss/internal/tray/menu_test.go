//go:build !headless

package tray

import (
	"errors"
	"testing"

	"github.com/gogpu/systray"
	clientconfig "github.com/nange/easyss/v3/client/config"
	"github.com/stretchr/testify/require"
)

func TestRadioMenuKeepsOneOptionSelected(t *testing.T) {
	menu := systray.NewMenu()
	var applied []string
	r := NewRadioMenu(menu, []RadioOption{
		{Key: "auto", Label: "自动", Checked: true},
		{Key: "direct", Label: "直接连接"},
	}, func(key string) { applied = append(applied, key) })

	r.selectKey("direct")

	require.Equal(t, []string{"direct"}, applied)
	require.False(t, r.items["auto"].IsChecked())
	require.True(t, r.items["direct"].IsChecked())

	// 点击已选中项：不重复应用，也不能把这一项取消掉。
	r.selectKey("direct")
	require.Equal(t, []string{"direct"}, applied)
	require.True(t, r.items["direct"].IsChecked())
}

func TestToggleCheckAppliesTheClickedState(t *testing.T) {
	item := systray.NewMenu().AddCheckbox("开关", false, nil)

	var got bool
	ToggleCheck(item, func(on bool) error {
		got = on
		return nil
	}, func(bool, error) {
		t.Fatal("apply must succeed")
	})

	require.True(t, got)
	require.True(t, item.IsChecked())
}

func TestToggleCheckRollsBackOnFailure(t *testing.T) {
	item := systray.NewMenu().AddCheckbox("开关", false, nil)
	failure := errors.New("boom")
	var gotOn bool
	var gotErr error

	ToggleCheck(item, func(bool) error { return failure }, func(on bool, err error) {
		gotOn, gotErr = on, err
	})

	require.False(t, item.IsChecked(), "失败后必须回到点击前的状态")
	require.True(t, gotOn)
	require.ErrorIs(t, gotErr, failure)
}

func TestServerMenuShowsConfiguredName(t *testing.T) {
	cfg := &clientconfig.ClientConfig{Servers: []*clientconfig.ServerProfile{
		{Host: "a.example", Port: 443, Name: "香港节点", Default: true},
		{Host: "b.example", Port: 443},
	}}
	s := NewServerMenu(systray.NewMenu(), cfg, func(int) {})

	require.Equal(t, []string{"香港节点", "b.example:443"}, s.labels)
	// 通知文案同时给出展示名与身份，未配 name 时不重复地址。
	require.Equal(t, "香港节点 (a.example:443)", s.DisplayName(0))
	require.Equal(t, "b.example:443", s.DisplayName(1))
	// name 只影响展示：勾选与切换仍按地址匹配。
	require.Equal(t, 0, s.IndexOf("a.example:443"))
	require.Equal(t, "a.example:443", s.Addr(0))
}

func TestServerMenuTracksSelection(t *testing.T) {
	cfg := &clientconfig.ClientConfig{Servers: []*clientconfig.ServerProfile{
		{Host: "a.example", Port: 443, Default: true},
		{Host: "b.example", Port: 443},
	}}
	s := NewServerMenu(systray.NewMenu(), cfg, func(int) {})

	require.Equal(t, 0, s.IndexOf("a.example:443"))
	require.Equal(t, 1, s.IndexOf("b.example:443"))
	require.Equal(t, -1, s.IndexOf("missing.example:443"))
	require.True(t, s.Checked(0))

	s.SetChecked(1)
	require.False(t, s.Checked(0))
	require.True(t, s.Checked(1))
	require.Equal(t, "b.example:443", s.Addr(1))
}

// TestServerMenuKeepsMetricsOnSelectedServer 固化"指标只属于当前选中项"：切换后旧行
// 必须回到纯标签（两行都带 ms/速度会让人以为两个服务器都在跑），新行等下一轮统计再填。
func TestServerMenuKeepsMetricsOnSelectedServer(t *testing.T) {
	cfg := &clientconfig.ClientConfig{Servers: []*clientconfig.ServerProfile{
		{Host: "a.example", Port: 443, Default: true},
		{Host: "b.example", Port: 443},
	}}
	s := NewServerMenu(systray.NewMenu(), cfg, func(int) {})

	s.updateMetrics(60, "649 B/s")
	require.Contains(t, titleAt(s, 0), "60ms")
	require.Equal(t, "b.example:443", titleAt(s, 1))

	s.SetChecked(1)
	require.Equal(t, "a.example:443", titleAt(s, 0), "旧服务器不能再带指标")
	require.Equal(t, "b.example:443", titleAt(s, 1), "新服务器等下一轮统计")

	s.updateMetrics(30, "1.2 KB/s")
	require.Equal(t, "a.example:443", titleAt(s, 0))
	require.Contains(t, titleAt(s, 1), "30ms")

	// 重复确认同一个选择不算切换：指标要保留，不能闪成纯标签。
	s.SetChecked(1)
	require.Contains(t, titleAt(s, 1), "30ms")
}

// titleAt 读条目当前应显示的标题：systray 不暴露 MenuItem 的 label，走同一份推导。
func titleAt(s *ServerMenu, idx int) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.titleLocked(idx)
}
