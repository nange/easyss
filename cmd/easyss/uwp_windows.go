//go:build windows && !without_tray

package main

import (
	"encoding/json"
	"sort"
	"strings"
	"sync"

	"fyne.io/systray"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/util"
)

type UWPApp struct {
	Name              string `json:"Name"`
	PackageFamilyName string `json:"PackageFamilyName"`
	Exempt            bool
}

type UWPMenuItem struct {
	MenuItem *systray.MenuItem
	App      *UWPApp
	Mu       sync.RWMutex
}

func (a *TrayApp) addUWPLoopbackMenu() {
	uwpMenu := systray.AddMenuItem("Windows UWP应用豁免", "")

	refreshItem := uwpMenu.AddSubMenuItem("刷新列表", "")
	systray.AddSeparator()

	var menuItems []*UWPMenuItem
	var mu sync.Mutex

	refreshFunc := func() {
		mu.Lock()
		defer mu.Unlock()

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

		appIndex := 0
		for _, app := range apps {
			if app.Name == "" || app.PackageFamilyName == "" {
				continue
			}

			if appIndex >= len(menuItems) {
				item := uwpMenu.AddSubMenuItemCheckbox(app.Name, "", app.Exempt)
				uwpItem := &UWPMenuItem{
					MenuItem: item,
					App:      &app,
				}
				menuItems = append(menuItems, uwpItem)

				go func(u *UWPMenuItem) {
					for {
						select {
						case <-u.MenuItem.ClickedCh:
							u.Mu.RLock()
							targetApp := u.App
							u.Mu.RUnlock()

							if targetApp == nil {
								continue
							}

							if u.MenuItem.Checked() {
								if err := removeLoopbackExempt(targetApp.PackageFamilyName); err != nil {
									log.Error("[UWP] Failed to remove exemption", "app", targetApp.Name, "err", err)
								} else {
									u.MenuItem.Uncheck()
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
									u.MenuItem.Check()
									log.Info("[UWP] Added exemption", "app", targetApp.Name)
									u.Mu.Lock()
									if u.App != nil {
										u.App.Exempt = true
									}
									u.Mu.Unlock()
								}
							}
						case <-a.closing:
							return
						}
					}
				}(uwpItem)

			} else {
				uwpItem := menuItems[appIndex]
				uwpItem.Mu.Lock()
				uwpItem.App = &app
				uwpItem.Mu.Unlock()

				uwpItem.MenuItem.SetTitle(app.Name)
				if app.Exempt {
					uwpItem.MenuItem.Check()
				} else {
					uwpItem.MenuItem.Uncheck()
				}
				uwpItem.MenuItem.Show()
			}
			appIndex++
		}

		for i := appIndex; i < len(menuItems); i++ {
			menuItems[i].MenuItem.Hide()
			menuItems[i].Mu.Lock()
			menuItems[i].App = nil
			menuItems[i].Mu.Unlock()
		}
	}

	go func() {
		for {
			select {
			case <-refreshItem.ClickedCh:
				log.Info("[UWP] Refreshing app list...")
				refreshFunc()
				log.Info("[UWP] Refresh complete")
			case <-a.closing:
				return
			}
		}
	}()

	go refreshFunc()
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
