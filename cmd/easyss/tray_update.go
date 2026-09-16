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
	// updateCheckDelay 是启动后多久执行第一次自动静默更新检查。
	updateCheckDelay = time.Minute
	// updateCheckInterval 是客户端持续运行时自动静默检查的重复间隔。
	// 桌面用户很少重启应用（尤其是 macOS 用户会连续运行数周），
	// 因此只在启动时检查一次会让新版本无限期地不被发现。
	updateCheckInterval = 24 * time.Hour
	// updateCheckJitter 是应用到每个周期间隔的相对抖动：
	// 否则所有运行中的客户端会在同一墙钟时间访问 GitHub API，
	// 同时它也让检查节奏看起来不像是固定信标。
	updateCheckJitter = 0.10
	// updateMenuReset 是临时结果（失败或已是最新）在菜单项重置前保持可见的时长。
	updateMenuReset = 4 * time.Second
	// updateNotifyTitle 是所有更新通知的标题，也是托盘 tooltip 中保留的标题。
	updateNotifyTitle = "Easyss"
	// updateTooltipMax 限制 tooltip 文本长度；Windows 上 NOTIFYICONDATA.szTip
	// 只能容纳 128 个 UTF-16 码元，因此在这里截断，
	// 而不是让系统外壳去截断。
	updateTooltipMax = 120
)

// 托盘更新状态机的各个状态。
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
		default: // 检查中或下载中：额外的点击被忽略
		}
	}()
}

// autoCheckUpdate 在进程整个生命周期内执行静默更新检查：
// 启动后不久一次，然后每隔 updateCheckInterval（±抖动）一次。
// 托盘客户端通常从不重启，因此只在启动时检查会隐藏之后的所有新版本。
// 开发构建（未注入 git tag）会跳过。
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

// runUpdateCheckLoop 先运行一次 check，然后每隔 a.updateCheckEvery 重复一次，
// 直到 a.closing 发出关闭信号。check 在循环 goroutine 上同步运行，
// 因此两次检查绝不会重叠，且下一次间隔只在上一次检查返回后开始。
func (a *TrayApp) runUpdateCheckLoop(check func()) {
	interval := a.updateCheckEvery
	if interval <= 0 {
		// 未通过 buildTray 构建的 TrayApp（测试）：回退到真实间隔，
		// 而不是让 NewTicker panic。
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

// timedUpdateCheckInterval 返回带 ±updateCheckJitter 随机抖动的周期检查间隔，
// 这样所有运行中的客户端不会在同一墙钟时间查询 release API。
func timedUpdateCheckInterval() time.Duration {
	factor := 1 + updateCheckJitter*(rand.Float64()*2-1)
	return time.Duration(float64(updateCheckInterval) * factor)
}

// checkUpdate 执行一次更新检查。它是同步的：调用方在自己的 goroutine 上运行它
// （托盘菜单处理器、周期循环），且更新状态机会让并发第二次调用变成空操作。
// ctx 限定检查的范围。只有交互式检查（菜单点击）会报告失败或已是最新的结果；
// 自动检查保持静默，除非出现新版本。
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
	// 周期性重新检测时也会调用：提醒渠道会被刷新（菜单项和 tooltip
	// 携带最新 tag），而系统通知每个 tag 只发一次。
	a.notifyUpdateAvailable(rel.TagName)
	log.Info("[SYSTRAY] new version available", "current", version.Tag(), "latest", rel.TagName)
}

// updateAvailableItemLabel 是有更新待处理时托盘菜单上显示的常驻标签。
func updateAvailableItemLabel(tag string) string {
	return fmt.Sprintf("发现新版本 %s，点击更新", tag)
}

// updateTooltipText 是有更新待处理时显示的 tooltip/悬停文本。
func updateTooltipText(tag string) string {
	text := fmt.Sprintf("%s: 发现新版本 %s，点击托盘菜单更新", updateNotifyTitle, tag)
	if len([]rune(text)) > updateTooltipMax {
		text = string([]rune(text)[:updateTooltipMax])
	}
	return text
}

// updateUpToDateText 是交互式检查未发现新版本后显示的通知。
// 临时菜单标签（"已是最新版本(...)"）会在 updateMenuReset 后重置，
// 因此没有通知的话，用户必须重新打开托盘菜单才能看到结果。
func updateUpToDateText(tag string) string {
	return fmt.Sprintf("已是最新版本(%s)", tag)
}

// notifyUser 显示系统通知并记入日志。尽力而为：
// gogpu/systray 会丢弃平台错误，因此日志条目是通知是否交给操作系统的唯一痕迹。
func (a *TrayApp) notifyUser(msg string) {
	log.Info("[SYSTRAY] notify", "msg", msg)
	a.tray.ShowNotification(updateNotifyTitle, msg)
}

// trayReady 报告 buildTray() 是否已完成。该检查是刻意的过度近似：
// a.tray 在 buildTray() 内、channel 关闭前不久被赋值，
// 因此理论上可能出现误报（在字段写入可见前就报告已就绪），
// 但手动检查只能由托盘菜单触发，而托盘菜单正是 buildTray() 自己构建的。
// 其他任何地方，该结果只控制可选通知，绝不控制流程。
func (a *TrayApp) trayReady() bool {
	select {
	case <-a.trayBuilt:
		return true
	default:
		return false
	}
}

// notifyUserSkipped 报告通知因托盘尚未就绪而被跳过；
// 调用方的日志和菜单标签仍会保留该结果。
func (a *TrayApp) notifyUserSkipped(msg string) {
	log.Warn("[SYSTRAY] notify skipped: tray not ready", "msg", msg)
}

// notifyOnInteractive 为用户点击托盘菜单项明确请求的结果显示通知。
// checkUpdate 只在交互式检查时调用它，因此静默的后台检查（启动或周期）
// 绝不会就失败或已是最新的结果发通知。托盘尚不可用时它保持静默。
func (a *TrayApp) notifyOnInteractive(msg string) {
	if !a.trayReady() {
		a.notifyUserSkipped(msg)
		return
	}
	a.notifyUser(msg)
}

// notifyUpdateAvailable 是"发现新版本"提醒的唯一入口。它按可靠性顺序组合了
// 四个渠道：
//
//  1. 托盘菜单项，在更新安装前一直存在（无 4 秒重置）且始终可达；
//  2. 绘制在托盘图标上的徽标，即使系统通知被禁用或被专注助手（Focus Assist）
//     抑制也可见；
//  3. 托盘 tooltip，供悬停图标的用户查看；
//  4. 一条系统通知（尽力而为：gogpu/systray 会丢弃通知错误，
//     操作系统也可能静默丢弃气泡提示，因此它既无法验证，也不能作为唯一渠道依赖）。
//
// 渠道 1-3 在每次检测时刷新，因此周期检查会让提醒始终指向最新版本。
// 渠道 4 每个 tag 只显示一次（见 shouldNotify）：忽略提醒的用户
// 不能在每个 updateCheckInterval 都为同一个 release 收到弹窗，
// 而比已通告版本更新的 release 会再次通知。
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

// shouldNotify 报告 tag 的"新版本"系统通知是否仍需显示，并记录之。
// tag 只在进程生命周期内被记住：手动检查或重启（二进制尚未更新）
// 会像之前一样再次提醒用户。
func (a *TrayApp) shouldNotify(tag string) bool {
	a.updateMu.Lock()
	defer a.updateMu.Unlock()
	if a.lastNotifiedTag == tag {
		return false
	}
	a.lastNotifiedTag = tag
	return true
}

// applyUpdateBadge 重新应用带更新徽标的托盘图标并更新 tooltip。
// 缺少图标渲染支持时会降级为仅 tooltip 提醒。
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

// clearUpdateBadge 在客户端更新后恢复普通托盘图标和 tooltip。
// 它是防御性的：成功安装后进程随即重启。
func (a *TrayApp) clearUpdateBadge() {
	a.updateUIMu.Lock()
	defer a.updateUIMu.Unlock()

	a.applyTrayIcon(icon.TrayData)
	a.tray.SetTooltip(updateNotifyTitle)
}

// applyTrayIcon 在所有平台上把 png 应用到托盘图标：macOS 使用模板（单色）图片，
// Windows/Linux 使用普通 PNG。同时设置暗色模式图标槽位，
// 这样 Windows 主题切换时不会用无徽标的图标覆盖徽标
// （该调用在其他平台上是空操作）。
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
		// 在重新启动前释放单例锁，这样新进程绝不会与旧进程
		// 竞争单例互斥锁。
		releaseSingletonLock()

		if err := selfupdate.Restart(); err != nil {
			// 新二进制已经就位；让旧版本继续在进程内运行，
			// 由用户手动重启。
			log.Error("[SYSTRAY] restart after update", "err", err)
			a.tray.ShowNotification("Easyss", "重启失败，请手动重启应用完成更新")
			// 单例锁在重新启动尝试前已释放；重新获取它，
			// 以便本进程在继续提供服务期间保持唯一实例。
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
		// 新进程已在运行；终止本进程。
		os.Exit(0)
	}()
}

// scheduleUpdateMenuReset 在临时结果（失败/已是最新）显示片刻后，
// 把更新菜单项恢复到空闲标签。
func (a *TrayApp) scheduleUpdateMenuReset() {
	time.AfterFunc(updateMenuReset, func() {
		if a.updateState.CompareAndSwap(updateStateChecking, updateStateIdle) {
			a.setUpdateItem("检查更新", false)
		}
	})
}

// setUpdateItem 更新更新菜单项。scheduleUpdateMenuReset 调度的重置
// 在定时器回调中运行，因此该保护可防止在更新项不存在时
// （托盘尚未构建）迟到的回调引发 panic。
func (a *TrayApp) setUpdateItem(label string, disabled bool) {
	if a.updateItem == nil {
		return
	}
	a.updateItem.SetLabel(label)
	a.updateItem.SetDisabled(disabled)
}
