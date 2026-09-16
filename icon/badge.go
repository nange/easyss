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
	// badgeInset 是徽章与图标边缘之间保留的像素间隙。
	badgeInset = 2
	// badgeMinRadius/badgeMaxRadius 约束徽章半径：在很小的图标上保持可见，
	// 在很大的图标上又不显突兀。
	badgeMinRadius = 3
	badgeMaxRadius = 6
	// badgeRadiusDivisor 使徽章相对图标成比例（约为较短边的 1/10）：
	// 32x32 -> 3px、44x44 -> 4px。
	badgeRadiusDivisor = 10
)

// badgeColor 是更新徽章的填充色。饱和的绿色在浅色和深色任务栏上都能看清。
var badgeColor = color.RGBA{R: 0x22, G: 0xC5, B: 0x5E, A: 0xFF}

// badgeOutline 比 badgeColor 向外扩一个像素绘制，使徽章在任意亮度的图标上都可见。
var badgeOutline = color.RGBA{R: 0xFF, G: 0xFF, B: 0xFF, A: 0xFF}

// UpdateBadge 返回 basePNG 的副本，并在其右上角绘制徽章，为托盘提供一个
// 不依赖系统通知是否开启的常驻"有更新可用"标记。
//
// 徽章大小与图标成比例（见 badgeRadius），因此同时适用于 32x32 的
// Windows/Linux 图标和 44x44 的 macOS 模板图标。结果可再次通过
// tray.SetIcon/SetTemplateIcon 应用；在 macOS 上轮廓与圆点都完全不透明，
// 这正是模板图像在菜单栏渲染出实心单色圆点所需的条件。
//
// 当 basePNG 无法解码时（例如非 PNG 资源）返回错误；调用方应退回到
// 仅提示气泡的提醒方式。
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

// badgeRadius 返回给定图标边长的徽章半径。
func badgeRadius(side int) int {
	return min(badgeMaxRadius, max(badgeMinRadius, side/badgeRadiusDivisor))
}

// fillCircle 以圆心 (cx, cy) 和半径 r 绘制一个实心圆。
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
