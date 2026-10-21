//go:build !headless

package main

import (
	"context"
	"fmt"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gogpu/systray"
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

// updateUI 是自更新用到的界面操作，生产实现是 trayShell。
type updateUI interface {
	notify(msg string)
	notifyIfReady(msg string)
	setIconAndTooltip(png []byte, tooltip string)
	setTooltip(text string)
}

var _ updateUI = (*trayShell)(nil)

// updateDeps 全部由构造方注入；closing 归调用方所有，测试可以自己关闭它。
type updateDeps struct {
	menu     *systray.Menu
	ui       updateUI
	port     func() int
	check    func(context.Context, *selfupdate.Client) (*selfupdate.Release, error)
	download func(context.Context, int, *selfupdate.Release) error
	// install 只在重启失败时返回：成功路径由实现直接退出进程，返回 nil 会让状态停在 Downloading。
	install func() error
	every   time.Duration // 必须为正，构造后不再变化
	closing <-chan struct{}
}

// updater 是自更新的状态机与"检查更新"菜单项。安装后的重启属于进程生命周期，
// 由 install 注入（TrayApp.restartAfterUpdate）。
type updater struct {
	item     *systray.MenuItem
	ui       updateUI
	port     func() int
	check    func(context.Context, *selfupdate.Client) (*selfupdate.Release, error)
	download func(context.Context, int, *selfupdate.Release) error
	install  func() error
	every    time.Duration
	closing  <-chan struct{}

	state atomic.Int32

	// 只保护 pendingUpdate 与 lastNotifiedTag。
	mu              sync.Mutex
	pendingUpdate   *selfupdate.Release
	lastNotifiedTag string
}

func newUpdater(d updateDeps) *updater {
	u := &updater{
		ui:       d.ui,
		port:     d.port,
		check:    d.check,
		download: d.download,
		install:  d.install,
		every:    d.every,
		closing:  d.closing,
	}
	// 菜单项在构造时建好：状态机每次写标签都假定它存在。
	u.item = d.menu.Add("检查更新", u.onUpdateClicked)
	return u
}

func (u *updater) onUpdateClicked() {
	go func() {
		switch u.state.Load() {
		case updateStateIdle:
			ctx, cancel := context.WithTimeout(context.Background(), selfupdate.CheckTimeout)
			defer cancel()
			u.checkUpdate(ctx, true)
		case updateStateAvailable:
			u.downloadAndInstall()
		}
	}()
}

// 进程生命周期内静默检查：启动后不久一次，之后每 updateCheckInterval（±抖动）一次。
func (u *updater) autoCheckUpdate() {
	if version.Tag() == "" {
		log.Info("[SYSTRAY] auto check update skipped: build has no version tag")
		return
	}
	select {
	case <-time.After(updateCheckDelay):
	case <-u.closing:
		return
	}
	u.runUpdateCheckLoop(func() { u.checkUpdate(context.Background(), false) })
}

// check 在循环 goroutine 上同步运行，因此两次检查绝不会重叠。
func (u *updater) runUpdateCheckLoop(run func()) {
	ticker := time.NewTicker(u.every)
	defer ticker.Stop()

	for {
		log.Info("[SYSTRAY] auto check update starting", "interval", u.every)
		run()

		select {
		case <-ticker.C:
		case <-u.closing:
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
func (u *updater) beginUpdateCheck() (wasAvailable, ok bool) {
	for {
		prev := u.state.Load()
		if prev != updateStateIdle && prev != updateStateAvailable {
			return false, false
		}
		if u.state.CompareAndSwap(prev, updateStateChecking) {
			return prev == updateStateAvailable, true
		}
	}
}

func (u *updater) pendingUpdateTag() string {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.pendingUpdate == nil {
		return ""
	}
	return u.pendingUpdate.TagName
}

// 调用前处于 Available 时必须回到 Available 并保留标签，降成 Idle 会让待处理更新从界面上消失。
func (u *updater) finishUpdateCheck(wasAvailable bool) {
	if !wasAvailable {
		u.scheduleUpdateMenuReset()
		return
	}
	tag := u.pendingUpdateTag()
	if tag == "" || !selfupdate.HasNewVersion(version.Tag(), tag) {
		u.scheduleUpdateMenuReset()
		return
	}
	u.state.Store(updateStateAvailable)
	u.setUpdateItem(updateAvailableItemLabel(tag), false)
}

// 同步执行，调用方在自己的 goroutine 上运行，更新状态机让并发的第二次调用变成空操作。
// 只有交互式检查会报告失败或已是最新。
func (u *updater) checkUpdate(ctx context.Context, interactive bool) {
	wasAvailable, ok := u.beginUpdateCheck()
	if !ok {
		return
	}
	if interactive {
		u.setUpdateItem("检查更新中...", true)
	}

	// 客户端持有自己的连接池，必须随本次检查回收：托盘长驻且检查可被反复手动触发。
	client := selfupdate.NewClient(u.port())
	defer client.Close()

	rel, err := u.check(ctx, client)
	if err != nil {
		log.Error("[SYSTRAY] check update", "err", err)
		if interactive {
			u.setUpdateItem("检查更新失败", true)
			u.ui.notifyIfReady("检查更新失败：" + err.Error())
		}
		u.finishUpdateCheck(wasAvailable)
		return
	}

	if !selfupdate.HasNewVersion(version.Tag(), rel.TagName) {
		if wasAvailable {
			// 周期检查且已有待处理更新：不要覆盖成"已是最新版本"。
			log.Info("[SYSTRAY] check update: no release newer than the pending update",
				"version", version.Tag(), "pending", u.pendingUpdateTag())
		} else {
			log.Info("[SYSTRAY] check update: already up to date", "version", version.Tag())
			if interactive {
				u.setUpdateItem(updateUpToDateText(version.Tag()), true)
				u.ui.notifyIfReady(updateUpToDateText(version.Tag()))
			}
		}
		u.finishUpdateCheck(wasAvailable)
		return
	}

	u.mu.Lock()
	u.pendingUpdate = rel
	u.mu.Unlock()
	u.state.Store(updateStateAvailable)
	u.notifyUpdateAvailable(rel.TagName)
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
func (u *updater) notifyUpdateAvailable(tag string) {
	u.setUpdateItem(updateAvailableItemLabel(tag), false)
	u.applyUpdateBadge(tag)
	if !u.shouldNotify(tag) {
		return
	}
	u.ui.notify(updateTooltipText(tag))
	log.Info("[SYSTRAY] update notification sent", "latest", tag,
		"channels", "system-notification,tray-badge,tray-tooltip,tray-menu-item")
}

// tag 只在进程生命周期内记住：手动检查或重启会再次提醒。
func (u *updater) shouldNotify(tag string) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.lastNotifiedTag == tag {
		return false
	}
	u.lastNotifiedTag = tag
	return true
}

// 缺少图标渲染支持时降级为仅 tooltip 提醒。
func (u *updater) applyUpdateBadge(tag string) {
	badged, err := icon.UpdateBadge(icon.TrayData)
	if err != nil {
		log.Warn("[SYSTRAY] update badge unavailable, falling back to tooltip", "err", err)
		u.ui.setTooltip(updateTooltipText(tag))
		return
	}

	u.ui.setIconAndTooltip(badged, updateTooltipText(tag))
}

// 防御性：成功安装后进程随即重启。
func (u *updater) clearUpdateBadge() {
	u.ui.setIconAndTooltip(icon.TrayData, trayAppName)
}

func (u *updater) downloadAndInstall() {
	u.mu.Lock()
	rel := u.pendingUpdate
	u.mu.Unlock()
	if rel == nil {
		return
	}
	if !u.state.CompareAndSwap(updateStateAvailable, updateStateDownloading) {
		return
	}
	u.setUpdateItem("正在下载 "+rel.TagName+" ...", true)

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), selfupdate.DownloadTimeout)
		defer cancel()
		u.runDownload(ctx, rel)
	}()
}

// 下载与安装在调用方 goroutine 上同步执行，失败要回到 Available，成功则由 install 决定是否退出进程。
func (u *updater) runDownload(ctx context.Context, rel *selfupdate.Release) {
	if err := u.download(ctx, u.port(), rel); err != nil {
		log.Error("[SYSTRAY] download and install update", "tag", rel.TagName, "err", err)
		u.setUpdateItem("更新 "+rel.TagName+" 失败，点击重试", false)
		u.state.Store(updateStateAvailable)
		u.ui.notify("更新失败：" + err.Error())
		return
	}

	log.Info("[SYSTRAY] update installed, restarting", "tag", rel.TagName)
	u.clearUpdateBadge()
	u.ui.notify("已更新到 " + rel.TagName + "，正在重启...")

	if err := u.install(); err != nil {
		u.ui.notify("重启失败，请手动重启应用完成更新")
		u.setUpdateItem("更新成功，重启失败，请手动重启", false)
		u.state.Store(updateStateAvailable)
	}
}

func (u *updater) scheduleUpdateMenuReset() {
	time.AfterFunc(updateMenuReset, func() {
		if u.state.CompareAndSwap(updateStateChecking, updateStateIdle) {
			u.setUpdateItem("检查更新", false)
		}
	})
}

func (u *updater) setUpdateItem(label string, disabled bool) {
	u.item.SetLabel(label)
	u.item.SetDisabled(disabled)
}
