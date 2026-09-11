package icon

import (
	"bytes"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/png"
)

const (
	// badgeInset is the gap in pixels kept between the badge and the icon edge.
	badgeInset = 2
	// badgeMinRadius/badgeMaxRadius bound the badge radius so it stays
	// visible on very small icons and unobtrusive on very large ones.
	badgeMinRadius = 3
	badgeMaxRadius = 6
	// badgeRadiusDivisor sizes the badge relative to the icon (roughly 1/10 of
	// the shorter side): 32x32 -> 4px, 44x44 -> 5px.
	badgeRadiusDivisor = 10
)

// badgeColor is the fill color of the update badge. A saturated green keeps
// the badge readable on both light and dark task bars.
var badgeColor = color.RGBA{R: 0x22, G: 0xC5, B: 0x5E, A: 0xFF}

// badgeOutline is drawn one pixel wider than badgeColor so the badge stays
// visible on top of icons of any luminance.
var badgeOutline = color.RGBA{R: 0xFF, G: 0xFF, B: 0xFF, A: 0xFF}

// UpdateBadge returns a copy of basePNG with a badge drawn in its top-right
// corner, giving the tray a persistent "update available" marker that does
// not depend on system notifications being enabled.
//
// The badge is sized proportionally to the icon (see badgeRadius), so it works
// for both the 32x32 Windows/Linux icon and the 44x44 macOS template icon. The
// result can be re-applied through tray.SetIcon/SetTemplateIcon; on macOS the
// outline and the dot are both fully opaque, which is what a template image
// needs in order to render a solid monochrome dot in the menu bar.
//
// An error is returned when basePNG cannot be decoded (for example a non-PNG
// asset); callers should then fall back to a tooltip-only reminder.
func UpdateBadge(basePNG []byte) ([]byte, error) {
	base, err := png.Decode(bytes.NewReader(basePNG))
	if err != nil {
		return nil, fmt.Errorf("decode tray icon: %w", err)
	}

	bounds := base.Bounds()
	out := image.NewRGBA(bounds)
	draw.Draw(out, bounds, base, bounds.Min, draw.Src)

	side := min(bounds.Dx(), bounds.Dy())
	r := badgeRadius(side)
	outline := r + 1
	cx := bounds.Max.X - (outline + badgeInset)
	cy := bounds.Min.Y + outline + badgeInset
	fillCircle(out, cx, cy, outline, badgeOutline)
	fillCircle(out, cx, cy, r, badgeColor)

	var buf bytes.Buffer
	if err := png.Encode(&buf, out); err != nil {
		return nil, fmt.Errorf("encode badged tray icon: %w", err)
	}
	return buf.Bytes(), nil
}

// badgeRadius returns the badge radius for the given icon side length.
func badgeRadius(side int) int {
	return min(badgeMaxRadius, max(badgeMinRadius, side/badgeRadiusDivisor))
}

// fillCircle paints a filled circle with center (cx, cy) and radius r.
func fillCircle(dst *image.RGBA, cx, cy, r int, c color.Color) {
	bounds := dst.Bounds()
	for y := cy - r; y <= cy+r; y++ {
		for x := cx - r; x <= cx+r; x++ {
			if !image.Pt(x, y).In(bounds) {
				continue
			}
			dx, dy := x-cx, y-cy
			if dx*dx+dy*dy <= r*r {
				dst.Set(x, y, c)
			}
		}
	}
}
