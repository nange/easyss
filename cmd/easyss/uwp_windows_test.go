//go:build windows && !headless

package main

import (
	"fmt"
	"testing"

	"github.com/gogpu/systray"
	"github.com/stretchr/testify/require"
)

// newTestUWPTrayApp builds a TrayApp with a fresh UWP submenu and its
// pre-built slot layout, without touching the real system tray.
func newTestUWPTrayApp() *TrayApp {
	a := &TrayApp{}
	a.uwpMenu = systray.NewMenu()
	a.buildUWPSlots()
	return a
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

func TestUWPBuildSlots(t *testing.T) {
	a := newTestUWPTrayApp()

	require.NotNil(t, a.uwpOverflowHint)
	require.True(t, a.uwpOverflowHint.IsDisabled())
	require.Len(t, a.uwpItems, uwpMenuSlots)
	for i, it := range a.uwpItems {
		require.NotNil(t, it.MenuItem, "slot %d missing menu item", i)
		require.True(t, it.MenuItem.IsDisabled(), "slot %d should start disabled", i)
		require.False(t, it.MenuItem.IsChecked(), "slot %d should start unchecked", i)
		require.Nil(t, it.App, "slot %d should start with no app", i)
	}
}

func TestUWPApplySlots_Overflow(t *testing.T) {
	a := newTestUWPTrayApp()
	apps := makeFakeUWPApps(uwpMenuSlots+6, 20)
	a.applyUWPAppsToSlots(apps)

	// All slots are populated (the overflow is dropped); the first 20 are
	// checked.
	for i := range uwpMenuSlots {
		require.False(t, a.uwpItems[i].MenuItem.IsDisabled(), "slot %d should be enabled", i)
		require.Equal(t, i < 20, a.uwpItems[i].MenuItem.IsChecked(), "slot %d checked", i)
		require.NotNil(t, a.uwpItems[i].App, "slot %d app", i)
		require.Equal(t, apps[i].PackageFamilyName, a.uwpItems[i].App.PackageFamilyName, "slot %d pfn", i)
	}
	// Overflow hint stays disabled: it is informational only.
	require.True(t, a.uwpOverflowHint.IsDisabled())
}

func TestUWPApplySlots_Partial(t *testing.T) {
	a := newTestUWPTrayApp()
	apps := makeFakeUWPApps(30, 5)
	a.applyUWPAppsToSlots(apps)

	for i := range 30 {
		require.False(t, a.uwpItems[i].MenuItem.IsDisabled(), "slot %d should be enabled", i)
		require.NotNil(t, a.uwpItems[i].App, "slot %d app", i)
	}
	for i := 30; i < uwpMenuSlots; i++ {
		require.True(t, a.uwpItems[i].MenuItem.IsDisabled(), "slot %d should stay disabled", i)
		require.Nil(t, a.uwpItems[i].App, "slot %d app should be nil", i)
	}
	// Overflow hint stays disabled: it is informational only.
	require.True(t, a.uwpOverflowHint.IsDisabled())
}

func TestUWPApplySlots_Empty(t *testing.T) {
	a := newTestUWPTrayApp()
	a.applyUWPAppsToSlots(nil)

	for i := range uwpMenuSlots {
		require.True(t, a.uwpItems[i].MenuItem.IsDisabled(), "slot %d should stay disabled", i)
		require.Nil(t, a.uwpItems[i].App, "slot %d app", i)
	}
}

func TestUWPApplySlots_SkipsInvalid(t *testing.T) {
	a := newTestUWPTrayApp()

	apps := []UWPApp{
		{Name: "", PackageFamilyName: "Bad.NoName_pkg"},   // skipped: no name
		{Name: "Good", PackageFamilyName: "Good.App_pkg"}, // fills slot 0
		{Name: "NoPfn", PackageFamilyName: ""},            // skipped: no PFN
	}
	a.applyUWPAppsToSlots(apps)

	require.False(t, a.uwpItems[0].MenuItem.IsDisabled())
	require.NotNil(t, a.uwpItems[0].App)
	require.Equal(t, "Good.App_pkg", a.uwpItems[0].App.PackageFamilyName)

	require.True(t, a.uwpItems[1].MenuItem.IsDisabled())
	require.Nil(t, a.uwpItems[1].App)
}

// TestUWPApplySlots_Twice ensures repeated refreshes are idempotent: the
// slot count never grows and disabled state converges after apps disappear.
func TestUWPApplySlots_Twice(t *testing.T) {
	a := newTestUWPTrayApp()

	a.applyUWPAppsToSlots(makeFakeUWPApps(10, 3))
	require.Len(t, a.uwpItems, uwpMenuSlots)

	a.applyUWPAppsToSlots(makeFakeUWPApps(8, 1))
	require.Len(t, a.uwpItems, uwpMenuSlots)
	for i := range 8 {
		require.False(t, a.uwpItems[i].MenuItem.IsDisabled(), "slot %d should be enabled", i)
	}
	for i := 8; i < 10; i++ {
		require.True(t, a.uwpItems[i].MenuItem.IsDisabled(), "slot %d should be disabled", i)
		require.Nil(t, a.uwpItems[i].App, "slot %d app should be nil", i)
	}
	// Slots beyond the previous fill are untouched.
	require.True(t, a.uwpItems[10].MenuItem.IsDisabled())
}
