//go:build !headless

package main

import (
	"context"
	"fmt"
	"math/rand/v2"
	"os"
	"runtime"
	"time"

	"github.com/nange/easyss/v3/icon"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/selfupdate"
	"github.com/nange/easyss/v3/version"
)

const (
	// updateCheckDelay is how long after startup the first automatic silent
	// update check runs.
	updateCheckDelay = time.Minute
	// updateCheckInterval is how often the automatic silent check repeats
	// while the client keeps running. Desktop users rarely restart the app
	// (macOS users in particular keep it alive for weeks), so a single
	// startup check would leave new releases unnoticed indefinitely.
	updateCheckInterval = 24 * time.Hour
	// updateCheckJitter is the relative spread applied to every periodic
	// interval: all running clients would otherwise hit the GitHub API at
	// the same wall-clock time, and it keeps the cadence from looking like
	// a fixed beacon.
	updateCheckJitter = 0.10
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
			ctx, cancel := context.WithTimeout(context.Background(), selfupdate.CheckTimeout)
			defer cancel()
			a.checkUpdate(ctx, true)
		case updateStateAvailable:
			a.downloadAndInstall()
		default: // checking or downloading: extra clicks are ignored
		}
	}()
}

// autoCheckUpdate performs silent update checks for the lifetime of the
// process: one shortly after startup and then one every updateCheckInterval
// (±jitter). A tray client is typically never restarted, so a startup-only
// check would hide every later release from the user. Development builds (no
// injected git tag) are skipped.
func (a *TrayApp) autoCheckUpdate() {
	if version.Tag() == "" {
		log.Info("[SYSTRAY] auto check update skipped: build has no version tag")
		return
	}
	select {
	case <-time.After(updateCheckDelay):
	case <-a.closing:
		return
	}
	a.runUpdateCheckLoop(func() { a.checkUpdate(context.Background(), false) })
}

// runUpdateCheckLoop runs check once, then repeats it every
// a.updateCheckEvery until a.closing signals shutdown. check runs
// synchronously on the loop goroutine, so two checks can never overlap and
// the next interval starts only after the previous check returned.
func (a *TrayApp) runUpdateCheckLoop(check func()) {
	interval := a.updateCheckEvery
	if interval <= 0 {
		// TrayApp built without buildTray (tests): fall back to the real
		// interval instead of letting NewTicker panic.
		interval = timedUpdateCheckInterval()
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		log.Info("[SYSTRAY] auto check update starting", "interval", interval)
		check()

		select {
		case <-ticker.C:
		case <-a.closing:
			return
		}
	}
}

// timedUpdateCheckInterval returns the periodic check interval with a random
// spread of ±updateCheckJitter, so that all running clients do not query the
// release API at the same wall-clock time.
func timedUpdateCheckInterval() time.Duration {
	factor := 1 + updateCheckJitter*(rand.Float64()*2-1)
	return time.Duration(float64(updateCheckInterval) * factor)
}

// checkUpdate performs one update check. It is synchronous: callers run it on
// their own goroutine (the tray menu handler, the periodic loop), and the
// update state machine makes a concurrent second call a no-op. ctx bounds the
// check. Only an interactive check (menu click) reports a failure or an
// up-to-date result; automatic checks stay silent unless a new version shows
// up.
func (a *TrayApp) checkUpdate(ctx context.Context, interactive bool) {
	if !a.updateState.CompareAndSwap(updateStateIdle, updateStateChecking) {
		return
	}
	if interactive {
		a.setUpdateItem("检查更新中...", true)
	}

	rel, err := a.checkLatest(ctx, selfupdate.NewClient(a.cfg.Local.HTTPPort))
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
	// Called for a periodic re-detection too: the reminder channels are
	// refreshed (the menu item and tooltip carry the newest tag), while the
	// system notification is one per tag.
	a.notifyUpdateAvailable(rel.TagName)
	log.Info("[SYSTRAY] new version available", "current", version.Tag(), "latest", rel.TagName)
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
// asked for by clicking the tray menu item. checkUpdate calls it only for an
// interactive check, so a silent background check (startup or periodic) never
// notifies about a failure or an up-to-date result. It stays silent when the
// tray is not usable yet.
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
//
// Channels 1-3 are refreshed on every detection, so a periodic check keeps the
// reminder pointing at the newest release. Channel 4 is shown once per tag
// (see shouldNotify): a user who ignores the reminder must not get a popup
// every updateCheckInterval for the very same release, while a release newer
// than the one already announced notifies again.
func (a *TrayApp) notifyUpdateAvailable(tag string) {
	a.setUpdateItem(updateAvailableItemLabel(tag), false)
	a.applyUpdateBadge(tag)
	if !a.shouldNotify(tag) {
		return
	}
	a.notifyUser(updateTooltipText(tag))
	log.Info("[SYSTRAY] update notification sent", "latest", tag,
		"channels", "system-notification,tray-badge,tray-tooltip,tray-menu-item")
}

// shouldNotify reports whether the "new version" system notification still has
// to be shown for tag, and records it. The tag is remembered for the lifetime
// of the process only: a manual check or a restart (the binary was not updated
// yet) reminds the user again, as before.
func (a *TrayApp) shouldNotify(tag string) bool {
	a.updateMu.Lock()
	defer a.updateMu.Unlock()
	if a.lastNotifiedTag == tag {
		return false
	}
	a.lastNotifiedTag = tag
	return true
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
			// The singleton lock was released before the relaunch attempt;
			// re-acquire it so this process stays the only instance while it
			// keeps serving.
			if lerr := tryAcquireSingletonLock(); lerr != nil {
				log.Error("[SYSTRAY] re-acquire singleton lock after failed restart", "err", lerr)
			}
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

// setUpdateItem updates the update menu entry. The reset scheduled by
// scheduleUpdateMenuReset runs in a timer callback, so the guard keeps a late
// callback from panicking when no update item exists (the tray was not built).
func (a *TrayApp) setUpdateItem(label string, disabled bool) {
	if a.updateItem == nil {
		return
	}
	a.updateItem.SetLabel(label)
	a.updateItem.SetDisabled(disabled)
}
