//go:build windows && !without_tray

package main

import (
	"encoding/json"
	"os/exec"
	"sort"
	"strings"
	"syscall"

	"github.com/getlantern/systray"
	"github.com/nange/easyss/v2/log"
)

type UWPApp struct {
	Name              string `json:"Name"`
	PackageFamilyName string `json:"PackageFamilyName"`
	Exempt            bool
}

func (st *SysTray) AddUWPLoopbackMenu() {
	uwpMenu := systray.AddMenuItem("Windows UWP应用豁免", "管理UWP应用豁免")
	systray.AddSeparator()

	// Initial loading in background
	go st.loadUWPApps(uwpMenu)
}

func (st *SysTray) loadUWPApps(parent *systray.MenuItem) {
	apps, err := getInstalledUWPApps()
	if err != nil {
		log.Error("[UWP] Failed to get installed UWP apps", "err", err)
		parent.AddSubMenuItem("Error loading apps", "").Disable()
		return
	}

	exemptsStr, err := getExemptUWPAppsOutput()
	if err != nil {
		log.Error("[UWP] Failed to get exempt UWP apps", "err", err)
		// Continue, assuming none exempt or error
	}

	exemptsStr = strings.ToLower(exemptsStr)

	for i := range apps {
		if strings.Contains(exemptsStr, strings.ToLower(apps[i].PackageFamilyName)) {
			apps[i].Exempt = true
		}
	}

	// Sort by Name
	sort.Slice(apps, func(i, j int) bool {
		return strings.ToLower(apps[i].Name) < strings.ToLower(apps[j].Name)
	})

	for _, app := range apps {
		if app.Name == "" || app.PackageFamilyName == "" {
			continue
		}

		item := parent.AddSubMenuItemCheckbox(app.Name, app.PackageFamilyName, app.Exempt)

		// Handle clicks
		go func(a UWPApp, m *systray.MenuItem) {
			for {
				select {
				case <-m.ClickedCh:
					if m.Checked() {
						// Uncheck -> Remove
						if err := removeLoopbackExempt(a.PackageFamilyName); err != nil {
							log.Error("[UWP] Failed to remove exemption", "app", a.Name, "err", err)
						} else {
							m.Uncheck()
							log.Info("[UWP] Removed exemption", "app", a.Name)
						}
					} else {
						// Check -> Add
						if err := addLoopbackExempt(a.PackageFamilyName); err != nil {
							log.Error("[UWP] Failed to add exemption", "app", a.Name, "err", err)
						} else {
							m.Check()
							log.Info("[UWP] Added exemption", "app", a.Name)
						}
					}
				case <-st.closing:
					return
				}
			}
		}(app, item)
	}
}

func getInstalledUWPApps() ([]UWPApp, error) {
	// PowerShell command to get apps (friendly names).
	// We use Get-StartApps to get user-facing apps with friendly names,
	// then parse the AppID to get PackageFamilyName.
	// We explicitly set OutputEncoding to UTF8 to avoid encoding issues on non-English systems.
	psScript := `[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; Get-StartApps | Select-Object Name, AppID | ConvertTo-Json`
	cmd := exec.Command("powershell", "-Command", psScript)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	type startApp struct {
		Name  string
		AppID string
	}

	var rawApps []startApp
	s := strings.TrimSpace(string(out))
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
	cmd := exec.Command("CheckNetIsolation", "LoopbackExempt", "-s")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func addLoopbackExempt(family string) error {
	cmd := exec.Command("CheckNetIsolation", "LoopbackExempt", "-a", "-n="+family)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd.Run()
}

func removeLoopbackExempt(family string) error {
	cmd := exec.Command("CheckNetIsolation", "LoopbackExempt", "-d", "-n="+family)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd.Run()
}
