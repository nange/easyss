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

	// 异步填充列表；菜单此时已显示 "刷新列表"。
	go a.uwpRefresh()
}

// refreshUWPAppItems 按当前已安装应用重建 UWP 子菜单的列表：已存在的条目就地更新，
// 新应用追加，已消失的应用置灰（systray 没有移除菜单项的 API）。重建安全的前提是
// nange/systray 修复了 issue #39：菜单显示期间的重建请求排队到关闭后再应用。
func (a *TrayApp) refreshUWPAppItems(apps []UWPApp) {
	needsRebuild := false
	appIndex := 0

	for i := range apps {
		app := &apps[i]
		if app.Name == "" || app.PackageFamilyName == "" {
			continue
		}

		if appIndex >= len(a.uwpItems) {
			uwpItem := &UWPMenuItem{App: app}
			item := a.uwpMenu.AddCheckbox(app.Name, app.Exempt, func(u *UWPMenuItem) func() {
				return func() { a.onUWPItemClicked(u) }
			}(uwpItem))
			uwpItem.MenuItem = item
			a.uwpItems = append(a.uwpItems, uwpItem)
			needsRebuild = true
		} else {
			uwpItem := a.uwpItems[appIndex]
			uwpItem.Mu.Lock()
			uwpItem.App = app
			uwpItem.Mu.Unlock()

			uwpItem.MenuItem.SetLabel(app.Name)
			uwpItem.MenuItem.SetDisabled(false)
			uwpItem.MenuItem.SetChecked(app.Exempt)
		}
		appIndex++
	}

	// 剩余条目对应的应用已不存在：置灰并清空目标应用，点击它们不会对任何应用生效。
	for i := appIndex; i < len(a.uwpItems); i++ {
		uwpItem := a.uwpItems[i]
		uwpItem.MenuItem.SetDisabled(true)
		uwpItem.Mu.Lock()
		uwpItem.App = nil
		uwpItem.Mu.Unlock()
	}

	if needsRebuild && a.tray != nil {
		// 重建发生在持有 uwpMu 期间：systray 会排队菜单显示期间的重建请求，不会与
		// 正在浏览菜单的用户竞争（托盘未构建时是无操作）。
		a.tray.SetMenu(a.rootMenu)
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

	a.refreshUWPAppItems(apps)
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
