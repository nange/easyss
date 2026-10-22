//go:build windows && !headless

package tray

import (
	"encoding/json"
	"sort"
	"strings"
	"sync"

	"github.com/gogpu/systray"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/util"
)

type UWPApp struct {
	Name              string `json:"Name"`
	PackageFamilyName string `json:"PackageFamilyName"`
	Exempt            bool
}

// UWP 是 Windows 专属的 UWP 豁免子菜单；非 Windows 的定义为空实现。
type UWP struct {
	mu      sync.Mutex
	menu    *systray.Menu
	items   []*uwpItem
	rebuild func() // 由托盘外壳注入：条目增长后重建整棵菜单树
}

// App 由刷新与点击两个 goroutine 共同读写，故单独加锁。
type uwpItem struct {
	MenuItem *systray.MenuItem
	App      *UWPApp
	Mu       sync.RWMutex
}

// Install 由 buildTray 在菜单组装阶段调用：只挂子菜单与"刷新列表"。
func (u *UWP) Install(root *systray.Menu, rebuild func()) {
	u.menu = systray.NewMenu()
	u.rebuild = rebuild
	root.AddSubmenu("Windows UWP应用豁免", u.menu)
	root.AddSeparator()

	u.menu.Add("刷新列表", func() { go u.refresh() })
}

// StartRefresh 在子菜单挂上托盘之后调用：填充列表会往菜单里追加条目，
// 与 Show 里的 SetMenu 并发会同时读写 Menu.Items。
func (u *UWP) StartRefresh() { go u.refresh() }

// refreshItems 按当前已安装应用重建 UWP 子菜单的列表：已存在的条目就地更新，
// 新应用追加，已消失的应用置灰（systray 没有移除菜单项的 API）。重建安全的前提是
// nange/systray 修复了 issue #39：菜单显示期间的重建请求排队到关闭后再应用。
// 调用方必须持有 u.mu；测试直接调用时不存在并发。
func (u *UWP) refreshItems(apps []UWPApp) {
	needsRebuild := false
	appIndex := 0

	for i := range apps {
		app := &apps[i]
		if app.Name == "" || app.PackageFamilyName == "" {
			continue
		}

		if appIndex >= len(u.items) {
			entry := &uwpItem{App: app}
			item := u.menu.AddCheckbox(app.Name, app.Exempt, func(target *uwpItem) func() {
				return func() { u.onItemClicked(target) }
			}(entry))
			entry.MenuItem = item
			u.items = append(u.items, entry)
			needsRebuild = true
		} else {
			entry := u.items[appIndex]
			entry.Mu.Lock()
			entry.App = app
			entry.Mu.Unlock()

			entry.MenuItem.SetLabel(app.Name)
			entry.MenuItem.SetDisabled(false)
			entry.MenuItem.SetChecked(app.Exempt)
		}
		appIndex++
	}

	// 剩余条目对应的应用已不存在：置灰并清空目标应用，点击它们不会对任何应用生效。
	for i := appIndex; i < len(u.items); i++ {
		entry := u.items[i]
		entry.MenuItem.SetDisabled(true)
		entry.Mu.Lock()
		entry.App = nil
		entry.Mu.Unlock()
	}

	// 重建发生在持有 u.mu 期间，不会与正在浏览菜单的用户竞争。
	if needsRebuild && u.rebuild != nil {
		u.rebuild()
	}
}

func (u *UWP) refresh() {
	u.mu.Lock()
	defer u.mu.Unlock()

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

	u.refreshItems(apps)
}

func (u *UWP) onItemClicked(entry *uwpItem) {
	go func() {
		entry.Mu.RLock()
		targetApp := entry.App
		entry.Mu.RUnlock()

		if targetApp == nil {
			return
		}

		if entry.MenuItem.IsChecked() {
			if err := removeLoopbackExempt(targetApp.PackageFamilyName); err != nil {
				log.Error("[UWP] Failed to remove exemption", "app", targetApp.Name, "err", err)
			} else {
				entry.MenuItem.SetChecked(false)
				log.Info("[UWP] Removed exemption", "app", targetApp.Name)
				entry.Mu.Lock()
				if entry.App != nil {
					entry.App.Exempt = false
				}
				entry.Mu.Unlock()
			}
		} else {
			if err := addLoopbackExempt(targetApp.PackageFamilyName); err != nil {
				log.Error("[UWP] Failed to add exemption", "app", targetApp.Name, "err", err)
			} else {
				entry.MenuItem.SetChecked(true)
				log.Info("[UWP] Added exemption", "app", targetApp.Name)
				entry.Mu.Lock()
				if entry.App != nil {
					entry.App.Exempt = true
				}
				entry.Mu.Unlock()
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
