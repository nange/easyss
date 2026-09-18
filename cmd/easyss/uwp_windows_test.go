//go:build windows && !headless

package main

import (
	"fmt"
	"testing"

	"github.com/gogpu/systray"
	"github.com/stretchr/testify/require"
)

// newTestUWPTrayApp 构建一个带有全新 UWP 子菜单的 TrayApp，不触碰真实的系统托盘。
func newTestUWPTrayApp() *TrayApp {
	a := &TrayApp{}
	a.uwpMenu = systray.NewMenu()
	return a
}

// rebuildUWPItems 是测试用的刷新入口：a.tray 为 nil，refreshUWPAppItems
// 内部的 SetMenu 因而不做任何事，测试只观察列表本身。
func rebuildUWPItems(a *TrayApp, apps []UWPApp) {
	a.refreshUWPAppItems(apps)
}

func makeFakeUWPApps(n, exemptCount int) []UWPApp {
	apps := make([]UWPApp, 0, n)
	for i := range n {
		apps = append(apps, UWPApp{
			Name:              fmt.Sprintf("App %03d", i),
			PackageFamilyName: fmt.Sprintf("Fake.App_%03d_pkg", i),
			Exempt:            i < exemptCount,
		})
	}
	return apps
}

func TestUWPItems_InitiallyEmpty(t *testing.T) {
	a := newTestUWPTrayApp()

	require.Empty(t, a.uwpItems)
}

func TestUWPItems_Append(t *testing.T) {
	a := newTestUWPTrayApp()
	apps := makeFakeUWPApps(30, 5)

	rebuildUWPItems(a, apps)

	// 列表不再有固定上限：所有应用都进入菜单。
	require.Len(t, a.uwpItems, len(apps))
	for i := range apps {
		require.NotNil(t, a.uwpItems[i].MenuItem, "item %d missing menu item", i)
		require.False(t, a.uwpItems[i].MenuItem.IsDisabled(), "item %d should be enabled", i)
		require.Equal(t, i < 5, a.uwpItems[i].MenuItem.IsChecked(), "item %d checked", i)
		require.NotNil(t, a.uwpItems[i].App, "item %d app", i)
		require.Equal(t, apps[i].PackageFamilyName, a.uwpItems[i].App.PackageFamilyName, "item %d pfn", i)
	}
}

func TestUWPItems_RefreshReusesExisting(t *testing.T) {
	a := newTestUWPTrayApp()
	first := makeFakeUWPApps(10, 3)
	rebuildUWPItems(a, first)

	items := make([]*systray.MenuItem, len(a.uwpItems))
	for i, it := range a.uwpItems {
		items[i] = it.MenuItem
	}

	// 应用数量不变：菜单项原地更新，不新增条目。
	second := makeFakeUWPApps(10, 7)
	rebuildUWPItems(a, second)

	require.Len(t, a.uwpItems, 10)
	for i := range second {
		require.Same(t, items[i], a.uwpItems[i].MenuItem, "item %d should be reused", i)
		require.False(t, a.uwpItems[i].MenuItem.IsDisabled(), "item %d should be enabled", i)
		require.Equal(t, i < 7, a.uwpItems[i].MenuItem.IsChecked(), "item %d checked", i)
	}
}

func TestUWPItems_RemovedAppGetsDisabled(t *testing.T) {
	a := newTestUWPTrayApp()
	rebuildUWPItems(a, makeFakeUWPApps(10, 3))

	rebuildUWPItems(a, makeFakeUWPApps(8, 1))

	// 已消失的应用条目保留在菜单里（systray 无法移除菜单项）但被置灰，
	// 且清空目标应用，点击它们不会对任何应用生效。
	require.Len(t, a.uwpItems, 10)
	for i := range 8 {
		require.False(t, a.uwpItems[i].MenuItem.IsDisabled(), "item %d should be enabled", i)
		require.NotNil(t, a.uwpItems[i].App, "item %d app", i)
	}
	for i := 8; i < 10; i++ {
		require.True(t, a.uwpItems[i].MenuItem.IsDisabled(), "item %d should be disabled", i)
		require.Nil(t, a.uwpItems[i].App, "item %d app should be nil", i)
	}
}

func TestUWPItems_EmptyRefreshDisablesAll(t *testing.T) {
	a := newTestUWPTrayApp()
	rebuildUWPItems(a, makeFakeUWPApps(5, 2))

	rebuildUWPItems(a, nil)

	require.Len(t, a.uwpItems, 5)
	for i := range a.uwpItems {
		require.True(t, a.uwpItems[i].MenuItem.IsDisabled(), "item %d should be disabled", i)
		require.Nil(t, a.uwpItems[i].App, "item %d app should be nil", i)
	}
}

// TestUWPItems_SkipsInvalid 确保缺少名称或 PackageFamilyName 的应用不会占据菜单项，
// 但合法的应用仍能全部进入列表。
func TestUWPItems_SkipsInvalid(t *testing.T) {
	a := newTestUWPTrayApp()

	apps := []UWPApp{
		{Name: "", PackageFamilyName: "Bad.NoName_pkg"}, // 跳过：无名称
		{Name: "Good", PackageFamilyName: "Good.App_pkg"},
		{Name: "NoPfn", PackageFamilyName: ""}, // 跳过：无 PFN
		{Name: "AlsoGood", PackageFamilyName: "Also.Good_pkg"},
	}

	rebuildUWPItems(a, apps)

	require.Len(t, a.uwpItems, 2)
	require.Equal(t, "Good.App_pkg", a.uwpItems[0].App.PackageFamilyName)
	require.Equal(t, "Also.Good_pkg", a.uwpItems[1].App.PackageFamilyName)
}

// TestUWPItems_GrowthAndShrink 覆盖典型的安装/卸载交替场景：
// 新增应用追加到列表末尾，卸载后回落到置灰状态而不是被删除。
func TestUWPItems_GrowthAndShrink(t *testing.T) {
	a := newTestUWPTrayApp()

	rebuildUWPItems(a, makeFakeUWPApps(3, 0))
	require.Len(t, a.uwpItems, 3)

	rebuildUWPItems(a, makeFakeUWPApps(6, 0))
	require.Len(t, a.uwpItems, 6)
	for i := 3; i < 6; i++ {
		require.False(t, a.uwpItems[i].MenuItem.IsDisabled(), "item %d should be enabled", i)
	}

	rebuildUWPItems(a, makeFakeUWPApps(2, 0))
	require.Len(t, a.uwpItems, 6)
	for i := 2; i < 6; i++ {
		require.True(t, a.uwpItems[i].MenuItem.IsDisabled(), "item %d should be disabled", i)
		require.Nil(t, a.uwpItems[i].App, "item %d app should be nil", i)
	}
}
