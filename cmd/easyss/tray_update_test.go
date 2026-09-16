//go:build !headless

package main

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

	"github.com/nange/easyss/v3/client/config"
	"github.com/nange/easyss/v3/icon"
	"github.com/nange/easyss/v3/selfupdate"
)

func TestUpdateAvailableLabels(t *testing.T) {
	label := updateAvailableItemLabel("v3.0.1")
	if label != "发现新版本 v3.0.1，点击更新" {
		t.Fatalf("unexpected menu label: %q", label)
	}

	tooltip := updateTooltipText("v3.0.1")
	if !strings.HasPrefix(tooltip, updateNotifyTitle+": ") {
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
	a := &TrayApp{closing: closing, updateCheckEvery: 10 * time.Millisecond}

	// 该循环只在关闭时停止，因此测试在自己的 goroutine 中运行它，并通过
	// closing channel 停止它。这里刻意测试 runUpdateCheckLoop 而不是
	// autoCheckUpdate：后者会先等待 updateCheckDelay（一分钟），并且对未注入
	// git tag 的构建会完全跳过该循环，两者都会使此测试变成空操作。
	// 这里的 check 回调故意使用桩函数：真实的 checkUpdate 路径会让更新状态
	// 保持为 "checking"，直到 4 秒后 scheduleUpdateMenuReset 触发，这会把
	// 一个定时器回调泄漏到测试二进制的其余部分。状态机本身由
	// TestCheckUpdateRequiresIdleState 覆盖。
	checked := make(chan struct{})
	var once sync.Once
	var checks atomic.Int64
	done := make(chan struct{})
	go func() {
		defer close(done)
		a.runUpdateCheckLoop(func() {
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
		got := timedUpdateCheckInterval()
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
	a := &TrayApp{}

	if !a.shouldNotify("v3.0.1") {
		t.Fatal("first notification for a tag should be shown")
	}
	if a.shouldNotify("v3.0.1") {
		t.Fatal("the same tag must not notify twice (e.g. on the next periodic check)")
	}
	if !a.shouldNotify("v3.0.2") {
		t.Fatal("a newer tag should notify again")
	}
}

func TestCheckUpdateRequiresIdleState(t *testing.T) {
	// 更新状态机是菜单处理器、周期循环和安装器之间的唯一守卫：当检查已经
	// 处于 "checking"（或 "available"/"downloading"）状态时，不得再次查询 API。
	var calls atomic.Int64
	a := &TrayApp{App: &App{cfg: &config.ClientConfig{}}}
	a.checkLatest = func(context.Context, *selfupdate.Client) (*selfupdate.Release, error) {
		calls.Add(1)
		return nil, errors.New("offline")
	}
	a.updateState.Store(updateStateDownloading)

	a.checkUpdate(context.Background(), false)

	if got := calls.Load(); got != 0 {
		t.Fatalf("checkLatest calls = %d, want 0 while an update is downloading", got)
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
	// 模板图标（macOS）是单色蒙版：透明度必须穿过角标叠加层保留下来，
	// 否则菜单栏会显示一个黑色方块。
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

// solidImage 返回一个用 c 填充的、指定大小的 PNG 编码图像。
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

// decodePNG 将 PNG 数据解码回图像，用于像素断言。
func decodePNG(t *testing.T, data []byte) image.Image {
	t.Helper()

	img, err := png.Decode(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("decode PNG: %v", err)
	}
	return img
}
