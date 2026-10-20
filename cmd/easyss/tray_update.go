//go:build !headless

package main

import (
	"context"
	"fmt"
	"math/rand/v2"
	"os"
	"time"

	"github.com/nange/easyss/v3/icon"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/selfupdate"
	"github.com/nange/easyss/v3/version"
)

const (
	updateCheckDelay = time.Minute
	// 桌面用户很少重启（macOS 上常连续运行数周），只在启动时检查会让新版本无限期不被发现。
	updateCheckInterval = 24 * time.Hour
	// 带抖动，否则所有运行中的客户端会同时访问 GitHub API，检查节奏也像固定信标。
	updateCheckJitter = 0.10
	updateMenuReset   = 4 * time.Second
	// Windows 的 NOTIFYICONDATA.szTip 只能容纳 128 个 UTF-16 码元，因此在交给外壳前截断。
	updateTooltipMax = 120
)

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
		default:
		}
	}()
}

// 进程生命周期内静默检查：启动后不久一次，之后每 updateCheckInterval（±抖动）一次。
func (a *TrayApp) autoCheckUpdate() {
	if version.Tag() == "" {
		log.Info("[SYSTRAY] auto check update skipped: build has no version tag")
		return
	}
	select {
	case <-time.After(updateCheckDelay):
	case <-a.shell.closing:
		return
	}
	a.runUpdateCheckLoop(func() { a.checkUpdate(context.Background(), false) })
}

// check 在循环 goroutine 上同步运行，因此两次检查绝不会重叠。
func (a *TrayApp) runUpdateCheckLoop(check func()) {
	interval := a.updateCheckEvery
	if interval <= 0 {
		// 未通过 buildTray 构建的 TrayApp（测试）回退到真实间隔，避免 NewTicker panic。
		interval = timedUpdateCheckInterval()
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		log.Info("[SYSTRAY] auto check update starting", "interval", interval)
		check()

		select {
		case <-ticker.C:
		case <-a.shell.closing:
			return
		}
	}
}

func timedUpdateCheckInterval() time.Duration {
	factor := 1 + updateCheckJitter*(rand.Float64()*2-1)
	return time.Duration(float64(updateCheckInterval) * factor)
}

// 接受 Idle 与 Available 两种起点：发现新版本后状态停在 Available，只接受 Idle 会让周期检查
// 被 CAS 永远挡掉。
func (a *TrayApp) beginUpdateCheck() (wasAvailable, ok bool) {
	for {
		prev := a.updateState.Load()
		if prev != updateStateIdle && prev != updateStateAvailable {
			return false, false
		}
		if a.updateState.CompareAndSwap(prev, updateStateChecking) {
			return prev == updateStateAvailable, true
		}
	}
}

func (a *TrayApp) pendingUpdateTag() string {
	a.updateMu.Lock()
	defer a.updateMu.Unlock()
	if a.pendingUpdate == nil {
		return ""
	}
	return a.pendingUpdate.TagName
}

// 调用前处于 Available 时必须回到 Available 并保留标签，降成 Idle 会让待处理更新从界面上消失。
func (a *TrayApp) finishUpdateCheck(wasAvailable bool) {
	if !wasAvailable {
		a.scheduleUpdateMenuReset()
		return
	}
	tag := a.pendingUpdateTag()
	if tag == "" || !selfupdate.HasNewVersion(version.Tag(), tag) {
		a.scheduleUpdateMenuReset()
		return
	}
	a.updateState.Store(updateStateAvailable)
	a.setUpdateItem(updateAvailableItemLabel(tag), false)
}

// 同步执行，调用方在自己的 goroutine 上运行，更新状态机让并发的第二次调用变成空操作。
// 只有交互式检查会报告失败或已是最新。
func (a *TrayApp) checkUpdate(ctx context.Context, interactive bool) {
	wasAvailable, ok := a.beginUpdateCheck()
	if !ok {
		return
	}
	if interactive {
		a.setUpdateItem("检查更新中...", true)
	}

	// 客户端持有自己的连接池，必须随本次检查回收：托盘长驻且检查可被反复手动触发。
	client := selfupdate.NewClient(a.currentConfig().Local.HTTPPort)
	defer client.Close()

	rel, err := a.checkLatest(ctx, client)
	if err != nil {
		log.Error("[SYSTRAY] check update", "err", err)
		if interactive {
			a.setUpdateItem("检查更新失败", true)
			a.shell.notifyIfReady("检查更新失败：" + err.Error())
		}
		a.finishUpdateCheck(wasAvailable)
		return
	}

	if !selfupdate.HasNewVersion(version.Tag(), rel.TagName) {
		if wasAvailable {
			// 周期检查且已有待处理更新：不要覆盖成"已是最新版本"。
			log.Info("[SYSTRAY] check update: no release newer than the pending update",
				"version", version.Tag(), "pending", a.pendingUpdateTag())
		} else {
			log.Info("[SYSTRAY] check update: already up to date", "version", version.Tag())
			if interactive {
				a.setUpdateItem(updateUpToDateText(version.Tag()), true)
				a.shell.notifyIfReady(updateUpToDateText(version.Tag()))
			}
		}
		a.finishUpdateCheck(wasAvailable)
		return
	}

	a.updateMu.Lock()
	a.pendingUpdate = rel
	a.updateMu.Unlock()
	a.updateState.Store(updateStateAvailable)
	a.notifyUpdateAvailable(rel.TagName)
	log.Info("[SYSTRAY] new version available", "current", version.Tag(), "latest", rel.TagName)
}

func updateAvailableItemLabel(tag string) string {
	return fmt.Sprintf("发现新版本 %s，点击更新", tag)
}

func updateTooltipText(tag string) string {
	text := fmt.Sprintf("%s: 发现新版本 %s，点击托盘菜单更新", trayAppName, tag)
	if len([]rune(text)) > updateTooltipMax {
		text = string([]rune(text)[:updateTooltipMax])
	}
	return text
}

// 临时菜单标签会在 updateMenuReset 后重置，所以必须同时发通知。
func updateUpToDateText(tag string) string {
	return fmt.Sprintf("已是最新版本(%s)", tag)
}

// "发现新版本"的唯一入口，四个渠道按可靠性排序：菜单项、图标徽标、tooltip、系统通知
// （尽力而为）。前三个每次检测都刷新，系统通知每个 tag 只发一次。
func (a *TrayApp) notifyUpdateAvailable(tag string) {
	a.setUpdateItem(updateAvailableItemLabel(tag), false)
	a.applyUpdateBadge(tag)
	if !a.shouldNotify(tag) {
		return
	}
	a.shell.notify(updateTooltipText(tag))
	log.Info("[SYSTRAY] update notification sent", "latest", tag,
		"channels", "system-notification,tray-badge,tray-tooltip,tray-menu-item")
}

// tag 只在进程生命周期内记住：手动检查或重启会再次提醒。
func (a *TrayApp) shouldNotify(tag string) bool {
	a.updateMu.Lock()
	defer a.updateMu.Unlock()
	if a.lastNotifiedTag == tag {
		return false
	}
	a.lastNotifiedTag = tag
	return true
}

// 缺少图标渲染支持时降级为仅 tooltip 提醒。
func (a *TrayApp) applyUpdateBadge(tag string) {
	badged, err := icon.UpdateBadge(icon.TrayData)
	if err != nil {
		log.Warn("[SYSTRAY] update badge unavailable, falling back to tooltip", "err", err)
		a.shell.setTooltip(updateTooltipText(tag))
		return
	}

	a.shell.setIconAndTooltip(badged, updateTooltipText(tag))
}

// 防御性：成功安装后进程随即重启。
func (a *TrayApp) clearUpdateBadge() {
	a.shell.setIconAndTooltip(icon.TrayData, trayAppName)
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

		if err := selfupdate.Update(ctx, a.currentConfig().Local.HTTPPort, rel); err != nil {
			log.Error("[SYSTRAY] download and install update", "tag", rel.TagName, "err", err)
			a.setUpdateItem("更新 "+rel.TagName+" 失败，点击重试", false)
			a.updateState.Store(updateStateAvailable)
			a.shell.notify("更新失败：" + err.Error())
			return
		}

		log.Info("[SYSTRAY] update installed, restarting", "tag", rel.TagName)
		a.clearUpdateBadge()
		a.shell.notify("已更新到 " + rel.TagName + "，正在重启...")

		// 与菜单切换服务器属同一类临界区：不共用会话序列锁会让两套停/起交错抢本地端口。
		a.sess.run(func() {
			a.Close()
			// 先释放单例锁，新进程才不会与旧进程竞争单例互斥锁。
			releaseSingletonLock()

			if err := selfupdate.Restart(); err != nil {
				// 新二进制已就位，让旧版本继续运行，由用户手动重启。
				log.Error("[SYSTRAY] restart after update", "err", err)
				a.shell.notify("重启失败，请手动重启应用完成更新")
				// 重新获取单例锁，本进程继续提供服务期间保持唯一实例。
				if lerr := tryAcquireSingletonLock(); lerr != nil {
					log.Error("[SYSTRAY] re-acquire singleton lock after failed restart", "err", lerr)
				}
				// 恢复路径不改变服务器：当前快照当作"意图"传入即可，只读其服务器下标。
				if err := a.restartService(a.currentConfig()); err != nil {
					log.Error("[SYSTRAY] restore service after failed restart", "err", err)
				}
				a.setUpdateItem("更新成功，重启失败，请手动重启", false)
				a.updateState.Store(updateStateAvailable)
				return
			}
			os.Exit(0)
		})
	}()
}

func (a *TrayApp) scheduleUpdateMenuReset() {
	time.AfterFunc(updateMenuReset, func() {
		if a.updateState.CompareAndSwap(updateStateChecking, updateStateIdle) {
			a.setUpdateItem("检查更新", false)
		}
	})
}

// 定时器回调中运行，因此要防住更新项尚不存在（托盘未构建）时迟到的回调 panic。
func (a *TrayApp) setUpdateItem(label string, disabled bool) {
	if a.updateItem == nil {
		return
	}
	a.updateItem.SetLabel(label)
	a.updateItem.SetDisabled(disabled)
}
