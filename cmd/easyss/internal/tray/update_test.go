//go:build !headless

package tray

import (
	"bytes"
	"context"
	"errors"
	"image"
	"image/color"
	"image/png"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gogpu/systray"
	"github.com/nange/easyss/v3/icon"
	"github.com/nange/easyss/v3/selfupdate"
)

// fakeUpdateUI 记录状态机写了哪些界面动作；真实托盘上的徽标与通知无法断言。
type fakeUpdateUI struct {
	notified     []string
	readyNotices []string
	badges       int
	badgeTooltip string
	tooltips     []string
}

func (f *fakeUpdateUI) Notify(msg string) { f.notified = append(f.notified, msg) }

func (f *fakeUpdateUI) NotifyIfReady(msg string) { f.readyNotices = append(f.readyNotices, msg) }

func (f *fakeUpdateUI) SetIconAndTooltip(_ []byte, tooltip string) {
	f.badges++
	f.badgeTooltip = tooltip
}

func (f *fakeUpdateUI) SetTooltip(text string) { f.tooltips = append(f.tooltips, text) }

func newTestUpdater(ui UpdateUI) *Updater {
	return NewUpdater(UpdateDeps{
		Menu: systray.NewMenu(),
		UI:   ui,
		Port: func() int { return 0 },
		Check: func(context.Context, *selfupdate.Client) (*selfupdate.Release, error) {
			return nil, errors.New("offline")
		},
		// 真实实现成功时会退出进程；测试若误走下载/重启路径，返回错误比 nil 更早暴露。
		Download: func(context.Context, int, *selfupdate.Release) error {
			return errors.New("download is not expected in this test")
		},
		Install: func() error { return errors.New("install is not expected in this test") },
		Every:   time.Hour,
		Closing: make(chan struct{}),
	})
}

func TestUpdateAvailableLabels(t *testing.T) {
	label := updateAvailableItemLabel("v3.0.1")
	if label != "发现新版本 v3.0.1，点击更新" {
		t.Fatalf("unexpected menu label: %q", label)
	}

	tooltip := updateTooltipText("v3.0.1")
	if !strings.HasPrefix(tooltip, AppName+": ") {
		t.Fatalf("tooltip should start with the app name: %q", tooltip)
	}
	if !strings.Contains(tooltip, "v3.0.1") {
		t.Fatalf("tooltip should carry the latest tag: %q", tooltip)
	}

	long := updateTooltipText(strings.Repeat("x", 500))
	if n := len([]rune(long)); n > updateTooltipMax {
		t.Fatalf("tooltip rune length = %d, want <= %d", n, updateTooltipMax)
	}
}

func TestUpdateUpToDateText(t *testing.T) {
	if got, want := updateUpToDateText("v3.0.1"), "已是最新版本(v3.0.1)"; got != want {
		t.Fatalf("unexpected up-to-date text: got %q, want %q", got, want)
	}
}

func TestUpdateCheckLoopRepeats(t *testing.T) {
	closing := make(chan struct{})
	u := NewUpdater(UpdateDeps{
		Menu: systray.NewMenu(),
		UI:   &fakeUpdateUI{},
		Port: func() int { return 0 },
		Check: func(context.Context, *selfupdate.Client) (*selfupdate.Release, error) {
			return nil, errors.New("offline")
		},
		Install: func() error { return nil },
		Every:   10 * time.Millisecond,
		Closing: closing,
	})

	// 测 runUpdateCheckLoop 而非 autoCheckUpdate：后者先等 updateCheckDelay（一分钟），且对未注入
	// git tag 的构建完全跳过循环。run 用桩函数——真实路径会把状态留在 "checking" 直到 4 秒后的
	// scheduleUpdateMenuReset，等于把定时器回调泄漏到测试二进制的其余部分。
	checked := make(chan struct{})
	var once sync.Once
	var checks atomic.Int64
	done := make(chan struct{})
	go func() {
		defer close(done)
		u.runUpdateCheckLoop(func() {
			if checks.Add(1) >= 2 {
				once.Do(func() { close(checked) })
			}
		})
	}()

	select {
	case <-checked:
	case <-time.After(2 * time.Second):
		t.Fatal("periodic update check did not repeat")
	}

	close(closing)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("check loop did not stop on shutdown")
	}
}

func TestTimedUpdateCheckIntervalJitter(t *testing.T) {
	minInterval := time.Duration(float64(updateCheckInterval) * (1 - updateCheckJitter))
	maxInterval := time.Duration(float64(updateCheckInterval) * (1 + updateCheckJitter))

	sawDifferent := false
	for range 50 {
		got := UpdateCheckInterval()
		if got < minInterval || got > maxInterval {
			t.Fatalf("interval %v outside [%v, %v]", got, minInterval, maxInterval)
		}
		if got != updateCheckInterval {
			sawDifferent = true
		}
	}
	if !sawDifferent {
		t.Fatal("jitter never changed the interval")
	}
}

func TestShouldNotifyOncePerTag(t *testing.T) {
	u := &Updater{}

	if !u.shouldNotify("v3.0.1") {
		t.Fatal("first notification for a tag should be shown")
	}
	if u.shouldNotify("v3.0.1") {
		t.Fatal("the same tag must not notify twice (e.g. on the next periodic check)")
	}
	if !u.shouldNotify("v3.0.2") {
		t.Fatal("a newer tag should notify again")
	}
}

func TestCheckUpdateRefusesActiveStates(t *testing.T) {
	// 状态机是菜单处理器、周期循环与安装器之间的唯一守卫：检查中与下载中不得再查 API。
	// Available 是例外——周期检查必须能从它重进 Checking，否则发现一次更新后再也看不到后续 release。
	var calls atomic.Int64
	u := newTestUpdater(&fakeUpdateUI{})
	u.check = func(context.Context, *selfupdate.Client) (*selfupdate.Release, error) {
		calls.Add(1)
		return nil, errors.New("offline")
	}
	u.state.Store(updateStateDownloading)

	u.checkUpdate(context.Background(), false)

	if got := calls.Load(); got != 0 {
		t.Fatalf("check calls = %d, want 0 while an update is downloading", got)
	}
}

// TestBeginUpdateCheckAcceptsAvailable 固定状态停在 Available 时下一次检查仍能进 Checking，
// 否则 24h 周期循环永远被 CAS 挡掉。
func TestBeginUpdateCheckAcceptsAvailable(t *testing.T) {
	u := &Updater{}
	u.state.Store(updateStateAvailable)

	wasAvailable, ok := u.beginUpdateCheck()
	if !ok {
		t.Fatal("check must be allowed to start while an update is available")
	}
	if !wasAvailable {
		t.Fatal("beginUpdateCheck must report that the previous state was Available")
	}
	if got := u.state.Load(); got != updateStateChecking {
		t.Fatalf("state = %d, want checking", got)
	}
}

// TestFinishUpdateCheckRestoresAvailable 固定没发现更新时也回到 Available 并保留菜单标签，不能丢掉待处理更新。
func TestFinishUpdateCheckRestoresAvailable(t *testing.T) {
	u := newTestUpdater(&fakeUpdateUI{})
	u.pendingUpdate = &selfupdate.Release{TagName: "v99.0.0"}
	u.state.Store(updateStateChecking)

	u.finishUpdateCheck(true)

	if got := u.state.Load(); got != updateStateAvailable {
		t.Fatalf("state = %d, want available", got)
	}
	if got := u.pendingUpdateTag(); got != "v99.0.0" {
		t.Fatalf("pending update = %q, want v99.0.0", got)
	}
}

// TestNotifyUpdateAvailableRefreshesBadgeOncePerTag 固定四个渠道的契约：徽标/tooltip/菜单项
// 每次检测都刷新，系统通知每个 tag 只发一次。
func TestNotifyUpdateAvailableRefreshesBadgeOncePerTag(t *testing.T) {
	ui := &fakeUpdateUI{}
	u := newTestUpdater(ui)

	u.notifyUpdateAvailable("v3.0.1")
	u.notifyUpdateAvailable("v3.0.1")

	if got := len(ui.notified); got != 1 {
		t.Fatalf("system notifications = %d, want 1 for a repeated tag", got)
	}
	if !strings.Contains(ui.notified[0], "v3.0.1") {
		t.Fatalf("notification lost the tag: %q", ui.notified[0])
	}
	if got := ui.badges + len(ui.tooltips); got != 2 {
		t.Fatalf("badge/tooltip refreshes = %d, want 2 (one per check)", got)
	}
	if ui.badges > 0 {
		if !strings.Contains(ui.badgeTooltip, "v3.0.1") {
			t.Fatalf("badge tooltip lost the tag: %q", ui.badgeTooltip)
		}
	} else if !strings.Contains(ui.tooltips[0], "v3.0.1") {
		t.Fatalf("fallback tooltip lost the tag: %q", ui.tooltips[0])
	}
}

// TestRunDownloadReportsDownloadFailure 固定下载失败要回到 Available 并让菜单项可重试。
func TestRunDownloadReportsDownloadFailure(t *testing.T) {
	ui := &fakeUpdateUI{}
	u := newTestUpdater(ui)
	u.download = func(context.Context, int, *selfupdate.Release) error {
		return errors.New("download failed")
	}
	u.install = func() error {
		t.Fatal("install must not run after a failed download")
		return nil
	}
	u.state.Store(updateStateDownloading)
	u.setUpdateItem("正在下载 v3.0.1 ...", true)

	u.runDownload(context.Background(), &selfupdate.Release{TagName: "v3.0.1"})

	if got := u.state.Load(); got != updateStateAvailable {
		t.Fatalf("state = %d, want available", got)
	}
	if u.item.IsDisabled() {
		t.Fatal("菜单项必须恢复为可点击")
	}
	if len(ui.notified) != 1 || !strings.Contains(ui.notified[0], "更新失败") {
		t.Fatalf("unexpected notifications: %q", ui.notified)
	}
}

// TestRunDownloadReportsRestartFailure 固定"下载成功但重启失败"的收尾：通知、菜单项与状态都要回滚。
func TestRunDownloadReportsRestartFailure(t *testing.T) {
	ui := &fakeUpdateUI{}
	u := newTestUpdater(ui)
	u.download = func(context.Context, int, *selfupdate.Release) error { return nil }
	u.install = func() error { return errors.New("restart failed") }
	u.state.Store(updateStateDownloading)
	u.setUpdateItem("正在下载 v3.0.1 ...", true)

	u.runDownload(context.Background(), &selfupdate.Release{TagName: "v3.0.1"})

	if got := u.state.Load(); got != updateStateAvailable {
		t.Fatalf("state = %d, want available", got)
	}
	if u.item.IsDisabled() {
		t.Fatal("菜单项必须恢复为可点击")
	}
	if len(ui.notified) != 2 {
		t.Fatalf("notifications = %q, want update + restart failure", ui.notified)
	}
	if !strings.Contains(ui.notified[0], "已更新到 v3.0.1") {
		t.Fatalf("first notification should report the installed tag: %q", ui.notified[0])
	}
	if !strings.Contains(ui.notified[1], "重启失败") {
		t.Fatalf("second notification should report the restart failure: %q", ui.notified[1])
	}
}

// TestInteractiveCheckReportsFailure 固定交互式检查的失败会经界面通知，而不是只写日志。
func TestInteractiveCheckReportsFailure(t *testing.T) {
	ui := &fakeUpdateUI{}
	u := newTestUpdater(ui)
	u.check = func(context.Context, *selfupdate.Client) (*selfupdate.Release, error) {
		return nil, errors.New("network down")
	}

	u.checkUpdate(context.Background(), true)

	if len(ui.readyNotices) != 1 {
		t.Fatalf("ready notices = %d, want 1", len(ui.readyNotices))
	}
	if !strings.Contains(ui.readyNotices[0], "检查更新失败") {
		t.Fatalf("unexpected failure notice: %q", ui.readyNotices[0])
	}
}

func TestUpdateBadge(t *testing.T) {
	base := solidImage(32, 32, color.RGBA{R: 0x12, G: 0x34, B: 0x56, A: 0xFF})

	badged, err := icon.UpdateBadge(base)
	if err != nil {
		t.Fatalf("UpdateBadge: %v", err)
	}

	img := decodePNG(t, badged)
	if got, want := img.Bounds(), image.Rect(0, 0, 32, 32); got != want {
		t.Fatalf("badged bounds = %v, want %v", got, want)
	}

	changed := false
	for y := 0; y < 16 && !changed; y++ {
		for x := 16; x < 32; x++ {
			r, _, _, _ := img.At(x, y).RGBA()
			if r != 0x1212 { // 8 位的 0x12 放大到 16 位
				changed = true
				break
			}
		}
	}
	if !changed {
		t.Fatal("badge did not change any pixel in the top-right area")
	}

	if r, g, b, a := img.At(0, 31).RGBA(); r != 0x1212 || g != 0x3434 || b != 0x5656 || a != 0xffff {
		t.Fatalf("badge leaked outside the top-right area: %v", color.RGBA64{R: uint16(r), G: uint16(g), B: uint16(b), A: uint16(a)})
	}
}

func TestUpdateBadgeKeepsTransparency(t *testing.T) {
	// 模板图标（macOS）是单色蒙版：透明度必须穿过角标叠加层，否则菜单栏显示一个黑色方块。
	transparent := image.NewRGBA(image.Rect(0, 0, 44, 44))
	var buf bytes.Buffer
	if err := png.Encode(&buf, transparent); err != nil {
		t.Fatalf("encode fixture: %v", err)
	}

	badged, err := icon.UpdateBadge(buf.Bytes())
	if err != nil {
		t.Fatalf("UpdateBadge: %v", err)
	}

	img := decodePNG(t, badged)
	if _, _, _, a := img.At(20, 42).RGBA(); a != 0 {
		t.Fatalf("alpha at (20,42) = %d, want 0", a)
	}

	badgeDrawn := false
	for y := range 44 {
		for x := range 44 {
			if _, _, _, a := img.At(x, y).RGBA(); a != 0 {
				badgeDrawn = true
				break
			}
		}
		if badgeDrawn {
			break
		}
	}
	if !badgeDrawn {
		t.Fatal("badge was not drawn on a transparent icon")
	}
}

func TestUpdateBadgeDecodeError(t *testing.T) {
	if _, err := icon.UpdateBadge([]byte("not a png")); err == nil {
		t.Fatal("UpdateBadge should fail on undecodable icon data")
	}
}

func solidImage(w, h int, c color.Color) []byte {
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := range h {
		for x := range w {
			img.Set(x, y, c)
		}
	}

	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

func decodePNG(t *testing.T, data []byte) image.Image {
	t.Helper()

	img, err := png.Decode(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("decode PNG: %v", err)
	}
	return img
}
