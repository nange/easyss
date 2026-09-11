//go:build !headless

package main

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/nange/easyss/v3/icon"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/selfupdate"
	"github.com/nange/easyss/v3/version"
)

const (
	// updateCheckDelay is how long after startup the automatic silent
	// update check runs.
	updateCheckDelay = time.Minute
	// updateMenuReset is how long a transient result (failure or
	// up-to-date) stays visible before the item resets.
	updateMenuReset = 4 * time.Second
	// updateNotifyTitle is the title of every update notification, and the
	// title kept in the tray tooltip.
	updateNotifyTitle = "Easyss"
	// updateTooltipMax bounds the tooltip text; NOTIFYICONDATA.szTip holds
	// 128 UTF-16 code units on Windows, so the truncation is applied here
	// instead of letting the shell cut it.
	updateTooltipMax = 120
)

// Tray update state machine states.
const (
	updateStateIdle int32 = iota
	updateStateChecking
	updateStateAvailable
	updateStateDownloading
)

func (a *TrayApp) onUpdateClicked() {
	go func() {
		switch a.updateState.Load() {
		case updateStateIdle:
			a.checkUpdate(true)
		case updateStateAvailable:
			a.downloadAndInstall()
		default: // checking or downloading: extra clicks are ignored
		}
	}()
}

// autoCheckUpdate performs one silent update check shortly after startup.
// Development builds (no injected git tag) are skipped.
func (a *TrayApp) autoCheckUpdate() {
	if version.Tag() == "" {
		log.Info("[SYSTRAY] auto check update skipped: build has no version tag")
		return
	}
	select {
	case <-time.After(updateCheckDelay):
		log.Info("[SYSTRAY] auto check update starting", "delay", updateCheckDelay)
		a.checkUpdate(false)
	case <-a.closing:
	}
}

func (a *TrayApp) checkUpdate(interactive bool) {
	if !a.updateState.CompareAndSwap(updateStateIdle, updateStateChecking) {
		return
	}
	if interactive {
		a.setUpdateItem("检查更新中...", true)
	}

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), selfupdate.CheckTimeout)
		defer cancel()

		rel, err := selfupdate.CheckLatest(ctx, selfupdate.NewClient(a.cfg.Local.HTTPPort))
		if err != nil {
			log.Error("[SYSTRAY] check update", "err", err)
			if interactive {
				a.setUpdateItem("检查更新失败", true)
				a.notifyOnInteractive("检查更新失败：" + err.Error())
			}
			a.scheduleUpdateMenuReset()
			return
		}

		if !selfupdate.HasNewVersion(version.Tag(), rel.TagName) {
			log.Info("[SYSTRAY] check update: already up to date", "version", version.Tag())
			if interactive {
				a.setUpdateItem(updateUpToDateText(version.Tag()), true)
				a.notifyOnInteractive(updateUpToDateText(version.Tag()))
			}
			a.scheduleUpdateMenuReset()
			return
		}

		a.updateMu.Lock()
		a.pendingUpdate = rel
		a.updateMu.Unlock()
		a.updateState.Store(updateStateAvailable)
		a.notifyUpdateAvailable(rel.TagName)
		log.Info("[SYSTRAY] new version available", "current", version.Tag(), "latest", rel.TagName)
	}()
}

// updateAvailableItemLabel is the persistent tray menu label shown while an
// update is pending.
func updateAvailableItemLabel(tag string) string {
	return fmt.Sprintf("发现新版本 %s，点击更新", tag)
}

// updateTooltipText is the tooltip/hover text shown while an update is pending.
func updateTooltipText(tag string) string {
	text := fmt.Sprintf("%s: 发现新版本 %s，点击托盘菜单更新", updateNotifyTitle, tag)
	if len([]rune(text)) > updateTooltipMax {
		text = string([]rune(text)[:updateTooltipMax])
	}
	return text
}

// updateUpToDateText is the notification shown after an interactive check that
// found no newer release. The transient menu label ("已是最新版本(...)")
// resets after updateMenuReset, so without a notification the user would have
// to reopen the tray menu to see the result.
func updateUpToDateText(tag string) string {
	return fmt.Sprintf("已是最新版本(%s)", tag)
}

// notifyUser shows a system notification and records it in the log. Best
// effort: gogpu/systray discards the platform error, so the log entry is the
// only trace of whether the notification was handed to the OS.
func (a *TrayApp) notifyUser(msg string) {
	log.Info("[SYSTRAY] notify", "msg", msg)
	a.tray.ShowNotification(updateNotifyTitle, msg)
}

// trayReady reports whether buildTray() has completed. The check is a
// deliberate over-approximation: a.tray is assigned inside buildTray() shortly
// before the channel is closed, so a false positive (ready reported just
// before the field write becomes visible) is theoretically possible, but a
// manual check can only be triggered from the tray menu, which buildTray()
// itself constructs. Everywhere else the result only gates optional
// notifications, never control flow.
func (a *TrayApp) trayReady() bool {
	select {
	case <-a.trayBuilt:
		return true
	default:
		return false
	}
}

// notifyUserSkipped reports that a notification was skipped because the tray
// was not ready yet; the caller's logs and menu label still carry the result.
func (a *TrayApp) notifyUserSkipped(msg string) {
	log.Warn("[SYSTRAY] notify skipped: tray not ready", "msg", msg)
}

// notifyOnInteractive shows a notification for a result the user explicitly
// asked for by clicking the tray menu item. It is a no-op for the automatic
// startup check, so a silent background check never notifies twice, and it
// stays silent when the tray is not usable yet.
func (a *TrayApp) notifyOnInteractive(msg string) {
	if !a.trayReady() {
		a.notifyUserSkipped(msg)
		return
	}
	a.notifyUser(msg)
}

// notifyUpdateAvailable is the single entry point of the "new version
// available" reminder. It combines four channels, in order of reliability:
//
//  1. the tray menu item, which persists until the update is installed (no
//     4s reset) and is always reachable;
//  2. a badge drawn onto the tray icon, which is visible even when system
//     notifications are disabled or Focus Assist suppresses them;
//  3. the tray tooltip, for users who hover the icon;
//  4. one system notification (best effort: gogpu/systray discards the
//     notification error and the OS may silently drop balloon tips, so it can
//     neither be verified nor relied upon as the only channel).
func (a *TrayApp) notifyUpdateAvailable(tag string) {
	a.setUpdateItem(updateAvailableItemLabel(tag), false)
	a.applyUpdateBadge(tag)
	a.notifyUser(updateTooltipText(tag))
	log.Info("[SYSTRAY] update notification sent", "latest", tag,
		"channels", "system-notification,tray-badge,tray-tooltip,tray-menu-item")
}

// applyUpdateBadge re-applies the tray icon with an update badge and updates
// the tooltip. Missing icon rendering support degrades to a tooltip-only
// reminder.
func (a *TrayApp) applyUpdateBadge(tag string) {
	a.updateUIMu.Lock()
	defer a.updateUIMu.Unlock()

	badged, err := icon.UpdateBadge(icon.TrayData)
	if err != nil {
		log.Warn("[SYSTRAY] update badge unavailable, falling back to tooltip", "err", err)
		a.tray.SetTooltip(updateTooltipText(tag))
		return
	}

	a.applyTrayIcon(badged)
	a.tray.SetTooltip(updateTooltipText(tag))
}

// clearUpdateBadge restores the plain tray icon and tooltip after the client
// has been updated. It is defensive: the process is restarted right after a
// successful install.
func (a *TrayApp) clearUpdateBadge() {
	a.updateUIMu.Lock()
	defer a.updateUIMu.Unlock()

	a.applyTrayIcon(icon.TrayData)
	a.tray.SetTooltip(updateNotifyTitle)
}

// applyTrayIcon applies png to the tray icon on every platform: macOS uses a
// template (monochrome) image, Windows/Linux a plain PNG. The dark mode slot
// is set as well so that a Windows theme switch cannot re-apply the unbadged
// icon over the badge (the call is a no-op on the other platforms).
func (a *TrayApp) applyTrayIcon(png []byte) {
	if runtime.GOOS == "darwin" {
		a.tray.SetTemplateIcon(png)
	} else {
		a.tray.SetIcon(png)
	}
	a.tray.SetDarkModeIcon(png)
}

func (a *TrayApp) downloadAndInstall() {
	a.updateMu.Lock()
	rel := a.pendingUpdate
	a.updateMu.Unlock()
	if rel == nil {
		return
	}
	if !a.updateState.CompareAndSwap(updateStateAvailable, updateStateDownloading) {
		return
	}
	a.setUpdateItem("正在下载 "+rel.TagName+" ...", true)

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), selfupdate.DownloadTimeout)
		defer cancel()

		if err := selfupdate.Update(ctx, a.cfg.Local.HTTPPort, rel); err != nil {
			log.Error("[SYSTRAY] download and install update", "tag", rel.TagName, "err", err)
			a.setUpdateItem("更新 "+rel.TagName+" 失败，点击重试", false)
			a.updateState.Store(updateStateAvailable)
			a.tray.ShowNotification("Easyss", "更新失败："+err.Error())
			return
		}

		log.Info("[SYSTRAY] update installed, restarting", "tag", rel.TagName)
		a.clearUpdateBadge()
		a.tray.ShowNotification("Easyss", "已更新到 "+rel.TagName+"，正在重启...")

		_ = a.setSysProxyOff()
		a.closeService()
		// Release before relaunch so the new process never races the old
		// one for the singleton mutex.
		releaseSingletonLock()

		if err := selfupdate.Restart(); err != nil {
			// The new binary is already in place; keep the old version
			// running in-process and let the user restart manually.
			log.Error("[SYSTRAY] restart after update", "err", err)
			a.tray.ShowNotification("Easyss", "重启失败，请手动重启应用完成更新")
			if err := a.restartService(a.cfg.Clone()); err != nil {
				log.Error("[SYSTRAY] restore service after failed restart", "err", err)
			}
			a.setUpdateItem("更新成功，重启失败，请手动重启", false)
			a.updateState.Store(updateStateAvailable)
			return
		}
		// The new process is running; terminate this one.
		os.Exit(0)
	}()
}

// scheduleUpdateMenuReset returns the update item to its idle label after a
// transient result (failure / up-to-date) has been visible for a moment.
func (a *TrayApp) scheduleUpdateMenuReset() {
	time.AfterFunc(updateMenuReset, func() {
		if a.updateState.CompareAndSwap(updateStateChecking, updateStateIdle) {
			a.setUpdateItem("检查更新", false)
		}
	})
}

func (a *TrayApp) setUpdateItem(label string, disabled bool) {
	a.updateItem.SetLabel(label)
	a.updateItem.SetDisabled(disabled)
}
