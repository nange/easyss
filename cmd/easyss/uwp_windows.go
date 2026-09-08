//go:build windows && !headless

package main

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/gogpu/systray"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/util"
)

const (
	// uwpMenuSlots is the fixed number of UWP-app checkbox slots pre-built
	// into the submenu at startup. The menu tree is never structurally
	// rebuilt at runtime: gogpu/systray's SetMenu renumbers every item
	// positionally and destroys the native HMENU, so a rebuild while the
	// context menu is open can dispatch a click to another item's callback
	// (https://github.com/gogpu/systray/issues/39). Pre-allocating a fixed
	// number of slots and only updating label/checked/disabled state in
	// place keeps the root menu shape constant, so no stale-ID aliasing is
	// possible. Any future feature that changes the menu tree structure at
	// runtime must respect the same constraint.
	uwpMenuSlots = 48

	// uwpSlotLoadingLabel is the placeholder shown in unpopulated slots
	// until the first refresh fills them in.
	uwpSlotLoadingLabel = "…"
)

func (a *TrayApp) addUWPLoopbackMenu(root *systray.Menu) {
	a.uwpMenu = systray.NewMenu()
	root.AddSubmenu("Windows UWP应用豁免", a.uwpMenu)
	root.AddSeparator()

	a.uwpMenu.Add("刷新列表", func() { go a.uwpRefresh() })

	a.buildUWPSlots()

	// Populate the list asynchronously; the menu already shows "刷新列表".
	go a.uwpRefresh()
}

// buildUWPSlots pre-builds the fixed slot layout of the UWP submenu: one
// overflow hint item followed by uwpMenuSlots checkbox slots, all disabled
// with a placeholder label. Slots are filled in place by applyUWPAppsToSlots,
// so the menu tree is never rebuilt after startup (see uwpMenuSlots).
func (a *TrayApp) buildUWPSlots() {
	a.uwpOverflowHint = a.uwpMenu.Add(uwpSlotLoadingLabel, nil)
	a.uwpOverflowHint.SetDisabled(true)

	a.uwpItems = make([]*UWPMenuItem, 0, uwpMenuSlots)
	for range uwpMenuSlots {
		uwpItem := &UWPMenuItem{}
		item := a.uwpMenu.AddCheckbox(uwpSlotLoadingLabel, false, func(u *UWPMenuItem) func() {
			return func() { a.onUWPItemClicked(u) }
		}(uwpItem))
		item.SetDisabled(true)
		uwpItem.MenuItem = item
		a.uwpItems = append(a.uwpItems, uwpItem)
	}
}

func (a *TrayApp) uwpRefresh() {
	a.uwpMu.Lock()
	defer a.uwpMu.Unlock()

	apps, err := getInstalledUWPApps()
	if err != nil {
		log.Error("[UWP] Failed to get installed UWP apps", "err", err)
		return
	}

	exemptsStr, err := getExemptUWPAppsOutput()
	if err != nil {
		log.Error("[UWP] Failed to get exempt UWP apps", "err", err)
	}
	exemptsStr = strings.ToLower(exemptsStr)

	for i := range apps {
		if strings.Contains(exemptsStr, strings.ToLower(apps[i].PackageFamilyName)) {
			apps[i].Exempt = true
		}
	}

	sort.Slice(apps, func(i, j int) bool {
		return strings.ToLower(apps[i].Name) < strings.ToLower(apps[j].Name)
	})

	a.applyUWPAppsToSlots(apps)
}

// applyUWPAppsToSlots writes apps into the pre-built slot layout in place.
// Apps beyond the slot count are dropped (reported by the overflow hint),
// and slots without a matching app stay disabled with their previous label.
// The menu tree shape is never changed here — no SetMenu, so the stale
// command-ID aliasing of gogpu/systray issue #39 cannot be triggered.
func (a *TrayApp) applyUWPAppsToSlots(apps []UWPApp) {
	slot := 0
	for i := range apps {
		if apps[i].Name == "" || apps[i].PackageFamilyName == "" {
			continue
		}
		if slot >= len(a.uwpItems) {
			break
		}
		app := &apps[i]
		uwpItem := a.uwpItems[slot]

		uwpItem.Mu.Lock()
		uwpItem.App = app
		uwpItem.Mu.Unlock()

		uwpItem.MenuItem.SetLabel(app.Name)
		uwpItem.MenuItem.SetDisabled(false)
		uwpItem.MenuItem.SetChecked(app.Exempt)
		slot++
	}

	// Slots without a corresponding app are disabled (their previous label
	// is preserved so the user still sees which app used to sit there).
	for i := slot; i < len(a.uwpItems); i++ {
		uwpItem := a.uwpItems[i]
		uwpItem.MenuItem.SetDisabled(true)
		uwpItem.Mu.Lock()
		uwpItem.App = nil
		uwpItem.Mu.Unlock()
	}

	if a.uwpOverflowHint != nil {
		if len(apps) > len(a.uwpItems) {
			a.uwpOverflowHint.SetLabel(fmt.Sprintf("共 %d 个应用，仅显示前 %d 个", len(apps), len(a.uwpItems)))
		} else {
			a.uwpOverflowHint.SetLabel(fmt.Sprintf("共 %d 个应用", len(apps)))
		}
		// The hint stays disabled: it is informational only, and clicking it
		// must never do anything.
	}
}

func (a *TrayApp) onUWPItemClicked(u *UWPMenuItem) {
	go func() {
		u.Mu.RLock()
		targetApp := u.App
		u.Mu.RUnlock()

		if targetApp == nil {
			return
		}

		if u.MenuItem.IsChecked() {
			if err := removeLoopbackExempt(targetApp.PackageFamilyName); err != nil {
				log.Error("[UWP] Failed to remove exemption", "app", targetApp.Name, "err", err)
			} else {
				u.MenuItem.SetChecked(false)
				log.Info("[UWP] Removed exemption", "app", targetApp.Name)
				u.Mu.Lock()
				if u.App != nil {
					u.App.Exempt = false
				}
				u.Mu.Unlock()
			}
		} else {
			if err := addLoopbackExempt(targetApp.PackageFamilyName); err != nil {
				log.Error("[UWP] Failed to add exemption", "app", targetApp.Name, "err", err)
			} else {
				u.MenuItem.SetChecked(true)
				log.Info("[UWP] Added exemption", "app", targetApp.Name)
				u.Mu.Lock()
				if u.App != nil {
					u.App.Exempt = true
				}
				u.Mu.Unlock()
			}
		}
	}()
}

func getInstalledUWPApps() ([]UWPApp, error) {
	psScript := `[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; Get-StartApps | Select-Object Name, AppID | ConvertTo-Json`
	out, err := util.Command("powershell", "-Command", psScript)
	if err != nil {
		return nil, err
	}

	type startApp struct {
		Name  string
		AppID string
	}

	var rawApps []startApp
	s := strings.TrimSpace(out)
	if len(s) == 0 {
		return nil, nil
	}

	if strings.HasPrefix(s, "{") {
		var app startApp
		if err := json.Unmarshal([]byte(s), &app); err != nil {
			return nil, err
		}
		rawApps = append(rawApps, app)
	} else if strings.HasPrefix(s, "[") {
		if err := json.Unmarshal([]byte(s), &rawApps); err != nil {
			return nil, err
		}
	}

	appMap := make(map[string]*UWPApp)
	for _, raw := range rawApps {
		if !strings.Contains(raw.AppID, "!") || !strings.Contains(raw.AppID, "_") {
			continue
		}

		parts := strings.Split(raw.AppID, "!")
		pfn := parts[0]

		if strings.ContainsAny(pfn, `/\`) {
			continue
		}

		if existing, ok := appMap[pfn]; ok {
			if !strings.Contains(existing.Name, raw.Name) {
				existing.Name += ", " + raw.Name
			}
		} else {
			appMap[pfn] = &UWPApp{
				Name:              raw.Name,
				PackageFamilyName: pfn,
			}
		}
	}

	var apps []UWPApp
	for _, app := range appMap {
		apps = append(apps, *app)
	}

	return apps, nil
}

func getExemptUWPAppsOutput() (string, error) {
	return util.Command("CheckNetIsolation", "LoopbackExempt", "-s")
}

func addLoopbackExempt(family string) error {
	_, err := util.Command("CheckNetIsolation", "LoopbackExempt", "-a", "-n="+family)
	return err
}

func removeLoopbackExempt(family string) error {
	_, err := util.Command("CheckNetIsolation", "LoopbackExempt", "-d", "-n="+family)
	return err
}
