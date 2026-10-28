//go:build windows && !headless

package tray

import (
	"fmt"
	"testing"

	"github.com/gogpu/systray"
	"github.com/stretchr/testify/require"
)

// newTestUWPMenu 只建子菜单容器，不走 install：install 会真的去查询已安装应用。
func newTestUWPMenu() *UWP {
	return &UWP{menu: systray.NewMenu()}
}

func rebuildUWPItems(u *UWP, apps []UWPApp) { u.refreshItems(apps) }

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
	u := newTestUWPMenu()

	require.Empty(t, u.items)
}

func TestUWPItems_Append(t *testing.T) {
	u := newTestUWPMenu()
	apps := makeFakeUWPApps(30, 5)

	rebuildUWPItems(u, apps)

	// 列表不再有固定上限：所有应用都进入菜单。
	require.Len(t, u.items, len(apps))
	for i := range apps {
		require.NotNil(t, u.items[i].MenuItem, "item %d missing menu item", i)
		require.False(t, u.items[i].MenuItem.IsDisabled(), "item %d should be enabled", i)
		require.Equal(t, i < 5, u.items[i].MenuItem.IsChecked(), "item %d checked", i)
		require.NotNil(t, u.items[i].App, "item %d app", i)
		require.Equal(t, apps[i].PackageFamilyName, u.items[i].App.PackageFamilyName, "item %d pfn", i)
	}
}

func TestUWPItems_RefreshReusesExisting(t *testing.T) {
	u := newTestUWPMenu()
	first := makeFakeUWPApps(10, 3)
	rebuildUWPItems(u, first)

	items := make([]*systray.MenuItem, len(u.items))
	for i, it := range u.items {
		items[i] = it.MenuItem
	}

	// 应用数量不变：菜单项原地更新，不新增条目。
	second := makeFakeUWPApps(10, 7)
	rebuildUWPItems(u, second)

	require.Len(t, u.items, 10)
	for i := range second {
		require.Same(t, items[i], u.items[i].MenuItem, "item %d should be reused", i)
		require.False(t, u.items[i].MenuItem.IsDisabled(), "item %d should be enabled", i)
		require.Equal(t, i < 7, u.items[i].MenuItem.IsChecked(), "item %d checked", i)
	}
}

func TestUWPItems_RemovedAppGetsDisabled(t *testing.T) {
	u := newTestUWPMenu()
	rebuildUWPItems(u, makeFakeUWPApps(10, 3))

	rebuildUWPItems(u, makeFakeUWPApps(8, 1))

	// 已消失的应用条目保留在菜单里（systray 无法移除菜单项）但被置灰，
	// 且清空目标应用，点击它们不会对任何应用生效。
	require.Len(t, u.items, 10)
	for i := range 8 {
		require.False(t, u.items[i].MenuItem.IsDisabled(), "item %d should be enabled", i)
		require.NotNil(t, u.items[i].App, "item %d app", i)
	}
	for i := 8; i < 10; i++ {
		require.True(t, u.items[i].MenuItem.IsDisabled(), "item %d should be disabled", i)
		require.Nil(t, u.items[i].App, "item %d app should be nil", i)
	}
}

func TestUWPItems_EmptyRefreshDisablesAll(t *testing.T) {
	u := newTestUWPMenu()
	rebuildUWPItems(u, makeFakeUWPApps(5, 2))

	rebuildUWPItems(u, nil)

	require.Len(t, u.items, 5)
	for i := range u.items {
		require.True(t, u.items[i].MenuItem.IsDisabled(), "item %d should be disabled", i)
		require.Nil(t, u.items[i].App, "item %d app should be nil", i)
	}
}

// TestUWPItems_SkipsInvalid 确保缺少名称或 PackageFamilyName 的应用不会占据菜单项，
// 但合法的应用仍能全部进入列表。
func TestUWPItems_SkipsInvalid(t *testing.T) {
	u := newTestUWPMenu()

	apps := []UWPApp{
		{Name: "", PackageFamilyName: "Bad.NoName_pkg"}, // 跳过：无名称
		{Name: "Good", PackageFamilyName: "Good.App_pkg"},
		{Name: "NoPfn", PackageFamilyName: ""}, // 跳过：无 PFN
		{Name: "AlsoGood", PackageFamilyName: "Also.Good_pkg"},
	}

	rebuildUWPItems(u, apps)

	require.Len(t, u.items, 2)
	require.Equal(t, "Good.App_pkg", u.items[0].App.PackageFamilyName)
	require.Equal(t, "Also.Good_pkg", u.items[1].App.PackageFamilyName)
}

// TestUWPItems_GrowthAndShrink 覆盖典型的安装/卸载交替场景：
// 新增应用追加到列表末尾，卸载后回落到置灰状态而不是被删除。
func TestUWPItems_GrowthAndShrink(t *testing.T) {
	u := newTestUWPMenu()

	rebuildUWPItems(u, makeFakeUWPApps(3, 0))
	require.Len(t, u.items, 3)

	rebuildUWPItems(u, makeFakeUWPApps(6, 0))
	require.Len(t, u.items, 6)
	for i := 3; i < 6; i++ {
		require.False(t, u.items[i].MenuItem.IsDisabled(), "item %d should be enabled", i)
	}

	rebuildUWPItems(u, makeFakeUWPApps(2, 0))
	require.Len(t, u.items, 6)
	for i := 2; i < 6; i++ {
		require.True(t, u.items[i].MenuItem.IsDisabled(), "item %d should be disabled", i)
		require.Nil(t, u.items[i].App, "item %d app should be nil", i)
	}
}

// TestUWPItems_RebuildOnlyWhenItemsGrow 守住重建只为新增条目发生：数量不变时重建
// 会让用户正在浏览的菜单反复排队。
func TestUWPItems_RebuildOnlyWhenItemsGrow(t *testing.T) {
	u := newTestUWPMenu()
	rebuilds := 0
	u.rebuild = func() { rebuilds++ }

	rebuildUWPItems(u, makeFakeUWPApps(3, 0))
	require.Equal(t, 1, rebuilds)

	rebuildUWPItems(u, makeFakeUWPApps(3, 1))
	require.Equal(t, 1, rebuilds, "条目数量不变时不应重建菜单")

	rebuildUWPItems(u, makeFakeUWPApps(4, 1))
	require.Equal(t, 2, rebuilds, "追加条目后必须重建菜单")
}

// TestUWPInstallWithoutElevationOnlyExplainsWhy 固定普通权限下的子菜单：豁免的增删要管理员
// 权限，列出可点击的条目只会让每次点击都静默失败（只留一行日志）。
func TestUWPInstallWithoutElevationOnlyExplainsWhy(t *testing.T) {
	u := &UWP{}
	u.install(systray.NewMenu(), func() { t.Error("普通权限下不应重建菜单") }, false)

	require.False(t, u.elevated)
	require.Empty(t, u.items)

	u.StartRefresh()
	require.Empty(t, u.items, "普通权限下不得启动 UWP 列表刷新")
}

// TestUWPInstallKeepsTheRefreshEntryWhenElevated 确认提权进程仍有完整的子菜单入口。
func TestUWPInstallKeepsTheRefreshEntryWhenElevated(t *testing.T) {
	u := &UWP{}
	u.install(systray.NewMenu(), nil, true)

	require.True(t, u.elevated)
	require.NotNil(t, u.menu)
}
