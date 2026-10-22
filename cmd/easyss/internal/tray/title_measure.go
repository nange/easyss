//go:build !headless

package tray

// 托盘菜单 label 的文本宽度度量。项目不使用 CGO，因此不调系统字体 API，而是用一张按
// macOS 13pt 菜单字体（.AppleSystemUIFont）逐字符实测的宽度表估算；"逐字符累加 vs
// 整串排版"的系统性偏差（kerning、亚像素取整）由 textEstimateScale 压掉。

const (
	// menuFontSpaceWidth 是实测的 U+0020 宽度（pt）。
	menuFontSpaceWidth = 3.5801
	// textEstimateScale 把逐字符实测折算成整串排版：逐字符累加系统性偏大（kerning
	// 与亚像素取整），用 30 个真实形态地址标定的最优系数是 0.985；取 1.0 偏差会翻倍。
	textEstimateScale = 0.985
	// widthUnit 是宽度表的单位：menuFontSpaceWidth/2048。
	widthUnit = menuFontSpaceWidth / 2048
)

// measureTextWidth 返回文本在托盘菜单字体下的显示宽度估算值（单位 pt）。
func measureTextWidth(s string) float64 {
	units := 0
	for _, r := range s {
		units += charWidth(r)
	}
	return float64(units) * widthUnit * textEstimateScale
}

// charWidth 返回字符宽度，单位为 widthUnit。ASCII 表由 macOS 13pt 菜单字体逐字符实测；
// 填充用空格用各自的实测宽度；其余表外字符按全角（1em）估算，见 fullWidthUnits。
func charWidth(r rune) int {
	if r < 0x20 || r > 0x7e {
		if units, ok := padSpaceWidth[r]; ok {
			return units
		}
		return fullWidthUnits
	}
	return asciiWidthUnits[r-0x20]
}

// fullWidthUnits 是表外字符（IDN 域名、emoji 等）的估算宽度，按 13pt 菜单字体的 CJK
// 全角字形实测 12.899pt 折算（约 7491，取 7490）。取 CJK 一档是因为地址里的非 ASCII
// 基本来自 IDN；低估会让指标列实际偏右且超长 IDN 不触发截断。
const fullWidthUnits = 7490

// padSpaceWidth 是填充用空格字符的宽度（单位 widthUnit），与 asciiWidthUnits 同一坐标系。
var padSpaceWidth = map[rune]int{
	'\u2003': 7506, // EM SPACE：实测 12.924pt
	'\u2002': 3731, // EN SPACE：实测 6.424pt
	'\u200a': 487,  // HAIR SPACE：实测 0.838pt
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
