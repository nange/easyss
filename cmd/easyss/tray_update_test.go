//go:build !headless

package main

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"strings"
	"testing"

	"github.com/nange/easyss/v3/icon"
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
			if r != 0x1212 { // 8-bit 0x12 scaled to 16 bits
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
	// A template icon (macOS) is a monochrome mask: transparency has to
	// survive the badge overlay, otherwise the menu bar shows a black square.
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

// solidImage returns an encoded PNG of the given size filled with c.
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

// decodePNG decodes PNG data back into an image for pixel assertions.
func decodePNG(t *testing.T, data []byte) image.Image {
	t.Helper()

	img, err := png.Decode(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("decode PNG: %v", err)
	}
	return img
}
