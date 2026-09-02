//go:build !headless

package main

import (
	"context"
	"os"
	"time"

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
		return
	}
	select {
	case <-time.After(updateCheckDelay):
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
			}
			a.scheduleUpdateMenuReset()
			return
		}

		if !selfupdate.HasNewVersion(version.Tag(), rel.TagName) {
			log.Info("[SYSTRAY] check update: already up to date", "version", version.Tag())
			if interactive {
				a.setUpdateItem("已是最新版本("+version.Tag()+")", true)
			}
			a.scheduleUpdateMenuReset()
			return
		}

		a.updateMu.Lock()
		a.pendingUpdate = rel
		a.updateMu.Unlock()
		a.updateState.Store(updateStateAvailable)
		a.setUpdateItem("发现新版本 "+rel.TagName+"，点击更新", false)
		a.tray.ShowNotification("Easyss", "发现新版本 "+rel.TagName+"，可在托盘菜单中点击更新")
		log.Info("[SYSTRAY] new version available", "current", version.Tag(), "latest", rel.TagName)
	}()
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
