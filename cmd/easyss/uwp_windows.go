//go:build windows && !without_tray

package main

import (
	"encoding/json"
	"sort"
	"strings"

	"sync"

	"github.com/getlantern/systray"
	"github.com/nange/easyss/v2/log"
	"github.com/nange/easyss/v2/util"
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

func (st *SysTray) AddUWPLoopbackMenu() {
	uwpMenu := systray.AddMenuItem("Windows UWP应用豁免", "管理UWP应用豁免")

	refreshItem := uwpMenu.AddSubMenuItem("刷新列表", "重新加载UWP应用列表")
	systray.AddSeparator() // Separator doesn't work well inside submenu on all platforms, but let's try.

	// Maintain a pool of menu items
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

		// Process apps
		for i := range apps {
			if strings.Contains(exemptsStr, strings.ToLower(apps[i].PackageFamilyName)) {
				apps[i].Exempt = true
			}
		}

		// Sort by Name
		sort.Slice(apps, func(i, j int) bool {
			return strings.ToLower(apps[i].Name) < strings.ToLower(apps[j].Name)
		})

		// Reuse or create items
		appIndex := 0
		for _, app := range apps {
			if app.Name == "" || app.PackageFamilyName == "" {
				continue
			}

			if appIndex >= len(menuItems) {
				// Create new item
				item := uwpMenu.AddSubMenuItemCheckbox(app.Name, app.PackageFamilyName, app.Exempt)
				uwpItem := &UWPMenuItem{
					MenuItem: item,
					App:      &app,
				}
				menuItems = append(menuItems, uwpItem)

				// Start loop for this new item
				go func(u *UWPMenuItem) {
					for {
						select {
						case <-u.MenuItem.ClickedCh:
							u.Mu.RLock()
							a := u.App
							u.Mu.RUnlock()

							if a == nil {
								continue
							}

							if u.MenuItem.Checked() {
								// Uncheck -> Remove
								if err := removeLoopbackExempt(a.PackageFamilyName); err != nil {
									log.Error("[UWP] Failed to remove exemption", "app", a.Name, "err", err)
								} else {
									u.MenuItem.Uncheck()
									log.Info("[UWP] Removed exemption", "app", a.Name)
									// Update internal state
									u.Mu.Lock()
									if u.App != nil {
										u.App.Exempt = false
									}
									u.Mu.Unlock()
								}
							} else {
								// Check -> Add
								if err := addLoopbackExempt(a.PackageFamilyName); err != nil {
									log.Error("[UWP] Failed to add exemption", "app", a.Name, "err", err)
								} else {
									u.MenuItem.Check()
									log.Info("[UWP] Added exemption", "app", a.Name)
									// Update internal state
									u.Mu.Lock()
									if u.App != nil {
										u.App.Exempt = true
									}
									u.Mu.Unlock()
								}
							}
						case <-st.closing:
							return
						}
					}
				}(uwpItem)

			} else {
				// Update existing item
				uwpItem := menuItems[appIndex]
				uwpItem.Mu.Lock()
				uwpItem.App = &app
				uwpItem.Mu.Unlock()

				uwpItem.MenuItem.SetTitle(app.Name)
				uwpItem.MenuItem.SetTooltip(app.PackageFamilyName)
				if app.Exempt {
					uwpItem.MenuItem.Check()
				} else {
					uwpItem.MenuItem.Uncheck()
				}
				uwpItem.MenuItem.Show()
			}
			appIndex++
		}

		// Hide unused items
		for i := appIndex; i < len(menuItems); i++ {
			menuItems[i].MenuItem.Hide()
			menuItems[i].Mu.Lock()
			menuItems[i].App = nil
			menuItems[i].Mu.Unlock()
		}
	}

	// Handle refresh click
	go func() {
		for {
			select {
			case <-refreshItem.ClickedCh:
				log.Info("[UWP] Refreshing app list...")
				refreshFunc()
				log.Info("[UWP] Refresh complete")
			case <-st.closing:
				return
			}
		}
	}()

	// Initial loading in background
	go refreshFunc()
}

func getInstalledUWPApps() ([]UWPApp, error) {
	// PowerShell command to get apps (friendly names).
	// We use Get-StartApps to get user-facing apps with friendly names,
	// then parse the AppID to get PackageFamilyName.
	// We explicitly set OutputEncoding to UTF8 to avoid encoding issues on non-English systems.
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

	// Filter and deduplicate
	appMap := make(map[string]*UWPApp)
	for _, raw := range rawApps {
		// AppID format for UWP: PackageFamilyName!AppId
		// Example: Microsoft.WindowsStore_8wekyb3d8bbwe!App
		// We verify it has "!" and "_" and looks like a PFN.
		if !strings.Contains(raw.AppID, "!") || !strings.Contains(raw.AppID, "_") {
			continue
		}

		parts := strings.Split(raw.AppID, "!")
		pfn := parts[0]

		// Basic validation of PFN (should contain underscore, and usually ends with 13 chars)
		// but checking for "_" is a good enough heuristic combined with "!" check for StartApps output.
		if strings.ContainsAny(pfn, `/\`) {
			// Skip paths
			continue
		}

		if existing, ok := appMap[pfn]; ok {
			// Deduplicate: Append name if different?
			// Or just ignore duplicates (e.g. Mail and Calendar might be separate items)
			// User preference: "Mail" and "Calendar" as separate items?
			// If we merge, we might get "Mail, Calendar".
			// Let's check if name is already contained.
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
