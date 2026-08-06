//go:build windows && !headless

package main

import (
	"encoding/json"
	"sort"
	"strings"

	"github.com/gogpu/systray"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/util"
)

func (a *TrayApp) addUWPLoopbackMenu(root *systray.Menu) {
	a.uwpMenu = systray.NewMenu()
	root.AddSubmenu("Windows UWP应用豁免", a.uwpMenu)
	root.AddSeparator()

	a.uwpMenu.Add("刷新列表", func() { go a.uwpRefresh() })

	// Populate the list asynchronously; the menu already shows "刷新列表".
	go a.uwpRefresh()
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

	// gogpu/systray builds the native menu (HMENU) on SetMenu; there is no
	// Show/Hide for menu items. Reuse existing items and append new ones,
	// then re-SetMenu only when the menu tree shape changed. Items that no
	// longer correspond to an installed app are disabled instead of hidden.
	needsRebuild := false
	appIndex := 0
	for _, app := range apps {
		if app.Name == "" || app.PackageFamilyName == "" {
			continue
		}

		if appIndex >= len(a.uwpItems) {
			uwpItem := &UWPMenuItem{App: &app}
			item := a.uwpMenu.AddCheckbox(app.Name, app.Exempt, func(u *UWPMenuItem) func() {
				return func() { a.onUWPItemClicked(u) }
			}(uwpItem))
			uwpItem.MenuItem = item
			item.SetChecked(app.Exempt)
			a.uwpItems = append(a.uwpItems, uwpItem)
			needsRebuild = true
		} else {
			uwpItem := a.uwpItems[appIndex]
			uwpItem.Mu.Lock()
			uwpItem.App = &app
			uwpItem.Mu.Unlock()

			uwpItem.MenuItem.SetLabel(app.Name)
			uwpItem.MenuItem.SetDisabled(false)
			uwpItem.MenuItem.SetChecked(app.Exempt)
		}
		appIndex++
	}

	for i := appIndex; i < len(a.uwpItems); i++ {
		uwpItem := a.uwpItems[i]
		uwpItem.MenuItem.SetDisabled(true)
		uwpItem.Mu.Lock()
		uwpItem.App = nil
		uwpItem.Mu.Unlock()
	}

	if needsRebuild && a.tray != nil {
		a.tray.SetMenu(a.rootMenu)
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
