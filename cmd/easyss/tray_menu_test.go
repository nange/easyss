//go:build !headless

package main

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
	r := newRadioMenu(menu, []radioOption{
		{key: "auto", label: "自动", checked: true},
		{key: "direct", label: "直接连接"},
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
	toggleCheck(item, func(on bool) error {
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

	toggleCheck(item, func(bool) error { return failure }, func(on bool, err error) {
		gotOn, gotErr = on, err
	})

	require.False(t, item.IsChecked(), "失败后必须回到点击前的状态")
	require.True(t, gotOn)
	require.ErrorIs(t, gotErr, failure)
}

func TestServerMenuTracksSelection(t *testing.T) {
	cfg := &clientconfig.ClientConfig{Servers: []*clientconfig.ServerProfile{
		{Host: "a.example", Port: 443, Default: true},
		{Host: "b.example", Port: 443},
	}}
	s := newServerMenu(systray.NewMenu(), cfg, func(int) {})

	require.Equal(t, 0, s.indexOf("a.example:443"))
	require.Equal(t, 1, s.indexOf("b.example:443"))
	require.Equal(t, -1, s.indexOf("missing.example:443"))
	require.True(t, s.checked(0))

	s.setChecked(1)
	require.False(t, s.checked(0))
	require.True(t, s.checked(1))
	require.Equal(t, "b.example:443", s.addr(1))
}
