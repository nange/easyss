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
	// uwpMenuSlots 是启动时预建进子菜单的 UWP 应用复选框槽位的固定数量。
	// 菜单树在运行时绝不会被结构性重建：gogpu/systray 的 SetMenu 会按位置
	// 重新编号每个菜单项并销毁原生 HMENU，因此在上下文菜单打开期间重建
	// 可能把一次点击派发到另一个菜单项的回调上
	// (https://github.com/gogpu/systray/issues/39)。预分配固定数量的槽位并
	// 只就地更新标签/选中/禁用状态，可保持根菜单形状不变，
	// 因此不会出现过期 ID 别名问题。任何将来要在运行时改变菜单树结构的
	// 特性都必须遵守同样的约束。
	uwpMenuSlots = 48

	// uwpSlotLoadingLabel 是显示在未填充槽位中的占位符，
	// 直到第一次刷新将其填满。
	uwpSlotLoadingLabel = "…"
)

func (a *TrayApp) addUWPLoopbackMenu(root *systray.Menu) {
	a.uwpMenu = systray.NewMenu()
	root.AddSubmenu("Windows UWP应用豁免", a.uwpMenu)
	root.AddSeparator()

	a.uwpMenu.Add("刷新列表", func() { go a.uwpRefresh() })

	a.buildUWPSlots()

	// 异步填充列表；菜单此时已显示 "刷新列表"。
	go a.uwpRefresh()
}

// buildUWPSlots 预建 UWP 子菜单的固定槽位布局：一个溢出提示项，
// 后跟 uwpMenuSlots 个复选框槽位，全部以占位符标签禁用。
// 槽位由 applyUWPAppsToSlots 就地填充，因此菜单树在启动后不会被重建
// （参见 uwpMenuSlots）。
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

// applyUWPAppsToSlots 将应用就地写入预建的槽位布局。
// 超出槽位数量的应用会被丢弃（由溢出提示项报告），
// 没有对应应用的槽位保持禁用并保留之前的标签。
// 此处绝不改变菜单树的形状——不调用 SetMenu，因此不会触发
// gogpu/systray issue #39 的过期命令 ID 别名问题。
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

	// 没有对应应用的槽位会被禁用（保留之前的标签，
	// 以便用户仍能看到哪个应用曾占据该位置）。
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
		// 提示项保持禁用：它仅供信息展示，点击它绝不能触发任何操作。
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
