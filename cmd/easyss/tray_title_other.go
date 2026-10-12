//go:build (!darwin || !cgo) && !headless

package main

// macOS 之外的构建（以及 darwin 上 CGO_ENABLED=0 的默认构建）没有平台字体度量，
// 这里用一张按 macOS 13pt 菜单字体（.AppleSystemUIFont）逐字符实测的宽度表做估算。
// 其他平台的字号/字形与 macOS 不完全相同，估算有偏差，但布局只依赖"把地址补到固定
// 列"这一相对关系，误差量级是几个 pt，视觉上仍然是一个稳定的列。
//
// 宽度表单位是 1/2048 个实测空格（见 widthUnit）；estimateTextWidth 输出的估算 pt
// 与 macOS cgo 实现的 measureTextWidth 同一坐标系。

const (
	// menuFontSpaceWidth 是实测的 U+0020 宽度（pt）。
	menuFontSpaceWidth = 3.5801
	// textEstimateScale 把"逐字符实测"折算成估算宽度：逐字符累加会系统性偏大
	// 约 1.5%（整串排版有 kerning 与亚像素取整），乘上它以后常见地址的估算误差
	// 在 ±2pt 内。
	textEstimateScale = 0.985
	// widthUnit 是宽度表的单位：menuFontSpaceWidth/2048。
	widthUnit = menuFontSpaceWidth / 2048
)

// measureTextWidth 返回文本宽度的估算值（单位 pt）。
func measureTextWidth(s string) float64 {
	units := 0
	for _, r := range s {
		units += charWidth(r)
	}
	return float64(units) * widthUnit * textEstimateScale
}

// charWidth 返回字符宽度，单位为 widthUnit。ASCII 表由 macOS 13pt 菜单字体逐字符
// 实测得到；用于填充的空格字符（不在 ASCII 表里）用各自的实测宽度，
// 其余表外字符（IDN 等）按全角估算。
func charWidth(r rune) int {
	if r < 0x20 || r > 0x7e {
		if units, ok := padSpaceWidth[r]; ok {
			return units
		}
		return 2 * 2048
	}
	return asciiWidthUnits[r-0x20]
}

// padSpaceWidth 是填充用空格字符的宽度（单位 widthUnit）。
var padSpaceWidth = map[rune]int{
	'\u2003': int(7506.0), // EM SPACE ≈ 12.924pt
	'\u2002': int(3731.0), // EN SPACE ≈ 6.424pt
	'\u200a': int(486.0),  // HAIR SPACE ≈ 0.838pt
}

// asciiWidthUnits 是 ASCII 0x20(' ')…0x7e('~') 逐字符实测宽度，单位为 1/2048 空格。
var asciiWidthUnits = [95]int{
	2048, 2270, 3508, 4641, 4641, 2878, 4321, 2164, // 空格 ! " # $ % & '
	2796, 2796, 3464, 4641, 2164, 3464, 2164, 2222, // ( ) * + , - . /
	4641, 3406, 4445, 4619, 4742, 4554, 4692, 4190, // 0 1 2 3 4 5 6 7
	4706, 4692, 2164, 2164, 4641, 4641, 4641, 3769, // 8 9 : ; < = > ?
	6783, 4967, 4844, 5280, 5360, 4386, 4212, 5509, // @ A B C D E F G
	5476, 1946, 3958, 4855, 4180, 6456, 5476, 5694, // H I J K L M N O
	4681, 5694, 4695, 4695, 4670, 5440, 4967, 7153, // P Q R S T U V W
	5004, 4830, 4877, 2474, 2222, 2474, 4641, 4296, // X Y Z [ \ ] ^ _
	3675, 4060, 4524, 4118, 4524, 4205, 2647, 4488, // ` a b c d e f g
	4332, 1794, 1790, 3994, 1837, 6427, 4296, 4350, // h i j k l m n o
	4495, 4488, 2789, 3849, 2658, 4296, 3987, 5716, // p q r s t u v w
	3856, 3994, 3965, 2796, 1881, 2796, 4641, // x y z { | } ~
}
