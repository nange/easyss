package handler

import (
	"encoding/binary"
	"math"
)

// 页面头部声明了 /favicon-<token>.ico，图标就必须真的存在：对一个被引用的静态资源回 HTML，
// 是最直白的"本站没有静态资源目录"证据。图标由部署种子生成，跨部署不同且与页面配色一致。

const (
	faviconSize = 16
	// ICONDIR（6 字节）+ 单条 ICONDIRENTRY（16 字节）。
	faviconHeaderLen = 22
	// BMP 内的 BITMAPINFOHEADER 长度。
	faviconBitmapInfoLen = 40
)

// newFavicon 生成单张 16×16、32bpp 的 ICO。图像段是 BMP 结构：BITMAPINFOHEADER +
// 自底向上的 BGRA 像素 + 1bpp AND 掩码（全 0 表示不透明），高度要写成像素高度的两倍。
func newFavicon(seed [32]byte, palette map[string]string) []byte {
	bg := rgbOf(palette["accent"], [3]byte{0x33, 0x37, 0x3d})
	fg := rgbOf(palette["surface"], [3]byte{0xf7, 0xf7, 0xf5})

	r := gen(seed, "favicon")
	shape, radius := r.IntN(3), 4+r.IntN(2)

	pixels := make([]byte, 0, faviconSize*faviconSize*4)
	for y := faviconSize - 1; y >= 0; y-- {
		for x := range faviconSize {
			c := bg
			if inFaviconShape(shape, x, y, radius) {
				c = fg
			}
			pixels = append(pixels, c[2], c[1], c[0], 0xff)
		}
	}
	// AND 掩码每行按 4 字节对齐：1bpp、16 像素 = 2 字节，补齐到 4 字节。
	andMask := make([]byte, faviconSize*4)

	image := make([]byte, faviconBitmapInfoLen, faviconBitmapInfoLen+len(pixels)+len(andMask))
	binary.LittleEndian.PutUint32(image[0:], faviconBitmapInfoLen)
	binary.LittleEndian.PutUint32(image[4:], faviconSize)
	binary.LittleEndian.PutUint32(image[8:], faviconSize*2)
	binary.LittleEndian.PutUint16(image[12:], 1)  // biPlanes
	binary.LittleEndian.PutUint16(image[14:], 32) // biBitCount
	image = append(image, pixels...)
	image = append(image, andMask...)

	ico := make([]byte, faviconHeaderLen, faviconHeaderLen+len(image))
	binary.LittleEndian.PutUint16(ico[2:], 1)   // type=1 表示图标
	binary.LittleEndian.PutUint16(ico[4:], 1)   // 图像数
	ico[6], ico[7] = faviconSize, faviconSize   // 宽、高
	binary.LittleEndian.PutUint16(ico[10:], 1)  // 颜色平面数
	binary.LittleEndian.PutUint16(ico[12:], 32) // 每像素位数
	binary.LittleEndian.PutUint32(ico[14:], uint32(len(image)))
	binary.LittleEndian.PutUint32(ico[18:], faviconHeaderLen) // 图像偏移
	return append(ico, image...)
}

// 16×16 上画不了细节，只用最简单的几何图形区分部署：圆形、菱形、方形。
func inFaviconShape(shape, x, y, radius int) bool {
	cx, cy := float64(x)-7.5, float64(y)-7.5
	switch shape {
	case 0:
		return math.Hypot(cx, cy) <= float64(radius)
	case 1:
		return math.Abs(cx)+math.Abs(cy) <= float64(radius+1)
	default:
		return math.Abs(cx) <= float64(radius+1) && math.Abs(cy) <= float64(radius+1)
	}
}

// rgbOf 解析调色板里的 #rrggbb；解析失败时用中性色，图标本身不能因此缺失。
func rgbOf(hex string, fallback [3]byte) [3]byte {
	r, g, b, ok := parseHex(hex)
	if !ok {
		return fallback
	}
	return [3]byte{byte(r), byte(g), byte(b)}
}
