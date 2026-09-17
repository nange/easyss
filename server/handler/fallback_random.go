package handler

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"html/template"
	"math"
	mrand "math/rand/v2"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nange/easyss/v3/log"
)

// 本文件负责"部署级身份"：每次服务端启动时用密码学随机的种子派生一套稳定的
// 可见身份（主题调色板、站点名、导航、备案文案、Last-Modified）。同一个部署内
// 所有客户端看到完全相同的页面，不同部署之间彼此不同。
//
// 为什么不注入"每次请求随机"的隐藏数据：真实静态站点对同一 URL 返回逐字节
// 相同的内容，同一路径每次都变反而是更强的自动化指纹，而且会让 htmlCache
// 失去意义。因此随机性只注入到"部署"这一层，路径映射仍由 hashIndex 确定性决定。
//
// 种子的唯一职责是可变性，不是保密：所有派生值都可能被观察者看到。

// ---------------------------------------------------------------------------
// 部署级状态
// ---------------------------------------------------------------------------

// deployment 是一次部署的完整伪装身份。字段在初始化后只读，因此并发读取安全；
// 初始化本身由 depOnce 保护。
type deployment struct {
	seed         [32]byte
	theme        themeDef
	site         siteIdentity
	nav          []navItem
	tagline      string
	lastModified time.Time
	footerNotice string
}

// fallbackVariant 是部署身份的种子来源。
//   - 生产路径使用零值：crypto/rand 生成种子、主题按种子抽取。
//   - 测试使用固定 Seed/Theme，从而得到完全可复现的输出。
type fallbackVariant struct {
	Seed  []byte
	Theme string
}

var (
	depOnce  sync.Once
	depState *deployment
)

// InitFallback 在服务器开始接受请求之前初始化部署级身份。
// 它只由 server 启动路径调用；ServeFallback 内部还有一层按需初始化兜底，
// 使直接调用它的测试也总能拿到可用状态。
func InitFallback() {
	initFallback(fallbackVariant{})
}

func initFallback(v fallbackVariant) {
	depOnce.Do(func() { depState = newDeployment(v) })
}

// currentDeployment 返回本部署的身份，必要时先完成初始化。
// 必须在任何渲染之前调用：主题与站点身份都来自它。
func currentDeployment() *deployment {
	initFallback(fallbackVariant{})
	return depState
}

func newDeployment(v fallbackVariant) *deployment {
	seed := initialSeed(v.Seed)
	theme := pickTheme(seed, v.Theme)
	theme.CSS = template.CSS(substituteTokens(string(theme.CSS), themePalette(seed, theme)))

	d := &deployment{
		seed:         seed,
		theme:        theme,
		site:         newSiteIdentity(seed),
		nav:          newNavItems(seed),
		tagline:      pickTagline(seed),
		lastModified: newLastModified(seed),
		footerNotice: newFooterNotice(seed),
	}
	log.Debug("[SERVER] fallback deployment identity",
		"theme", theme.Name, "site", d.site.Name,
		"last_modified", d.lastModified.UTC().Format(time.RFC3339))
	return d
}

// initialSeed 返回本次部署的随机种子。测试可以通过 variant.Seed 注入固定值。
func initialSeed(injected []byte) [32]byte {
	var seed [32]byte
	if len(injected) > 0 {
		if len(injected) == len(seed) {
			copy(seed[:], injected)
			return seed
		}
		// 注入值较短时用 SHA-256 扩展，保证任意长度输入都得到均匀 32 字节。
		return sha256.Sum256(injected)
	}
	if _, err := rand.Read(seed[:]); err != nil {
		// crypto/rand 在受支持的平台上不会失败；真失败了也不能退化成时间戳之类
		// 可预测的兜底值，那会把"部署级随机"降级成可枚举特征。
		panic(fmt.Sprintf("fallback seed: %v", err))
	}
	return seed
}

// gen 派生一个用途隔离的随机源：先做域分离再喂给 ChaCha8。这样新增一个随机
// 消费点不会改变其它用途的输出——htmlCache 溢出后重算、以及测试中的复现
// 都依赖这一点。
func gen(seed [32]byte, purpose string) *mrand.Rand {
	key := sha256.Sum256(append([]byte(purpose+"\x00"), seed[:]...))
	return mrand.New(mrand.NewChaCha8(key))
}

// pickRand 从池中随机取一个元素；池为空时返回零值而不是 panic
// （rand.IntN(0) 会 panic，而内容池是可被运维编辑的资源文件）。
func pickRand[T any](r *mrand.Rand, pool []T) T {
	var zero T
	if len(pool) == 0 {
		return zero
	}
	return pool[r.IntN(len(pool))]
}

// ---------------------------------------------------------------------------
// 主题选择与调色板
// ---------------------------------------------------------------------------

// pickTheme 选择本次部署的主题。name 非空时按名字固定（测试用），
// 名字不存在时回退到随机选择。
func pickTheme(seed [32]byte, name string) themeDef {
	if name != "" {
		for _, t := range themes {
			if t.Name == name {
				return t
			}
		}
	}
	return themes[gen(seed, "theme").IntN(len(themes))]
}

// fontStacks 是 body 字体栈池。混用衬线、无衬线和等宽栈，使不同部署的页面
// 不具有统一的排版特征。
var fontStacks = []string{
	`-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif`,
	`Georgia,"Times New Roman",serif`,
	`ui-sans-serif,system-ui,-apple-system,sans-serif`,
	`Cambria,"Hoefler Text",Utopia,"Liberation Serif","Times New Roman",serif`,
	`"Helvetica Neue",Helvetica,Arial,sans-serif`,
	`"Segoe UI",Tahoma,Geneva,Verdana,sans-serif`,
	`Charter,"Bitstream Charter",Georgia,serif`,
	`"Palatino Linotype",Palatino,"Book Antiqua",Georgia,serif`,
}

// themePalette 为给定主题派生一套自洽的调色板与排版参数。
//
// 规则是"整站同一个色相族 + 按语义分档明度 + 相对亮度边界",而不是逐项随机
// 撞色：所有颜色由同一个色相派生，每一处"文字/背景"配对都按相对亮度夹紧，
// 保证任何一次派生都得到可读、看起来像人配的配色。
func themePalette(seed [32]byte, theme themeDef) map[string]string {
	r := gen(seed, "palette")

	light := theme.Mode != "dark"
	hue := float64(r.IntN(360))
	baseSat := 30 + float64(r.IntN(26)) // 30-55%
	textSat := float64(r.IntN(12))      // 正文基本中性，避免整页泛色

	// bg/surface 是其余配对的参照背景，先定下来。
	// 除背景外的每个取值都用相对亮度做窗口约束，而不是凭感知明度的经验值：
	// 亮度可以直接换成对比度，因此"可读"这件事是可验证的，而不是靠调参。
	var bg, surface, text, textMuted, border string
	if light {
		bg = hexHSL(hue, math.Max(baseSat*0.25, 8), 97+float64(r.IntN(2)))
		surface = hexHSL(hue, 0, 100)
		text = capLuminance(hexHSL(hue, textSat, 26), 0.15)
		textMuted = capLuminance(hexHSL(hue, 10+float64(r.IntN(8)), 58), 0.15)
		border = capLuminance(hexHSL(hue, 12+float64(r.IntN(10)), 84), 0.40)
	} else {
		bg = hexHSL(hue, math.Max(baseSat*0.25, 8), 6+float64(r.IntN(3)))
		surface = hexHSL(hue, 0, 9+float64(r.IntN(3)))
		text = boostLuminance(hexHSL(hue, textSat, 90), 0.70)
		textMuted = boostLuminance(hexHSL(hue, 10+float64(r.IntN(8)), 66), 0.30)
		border = boostLuminance(hexHSL(hue, 12+float64(r.IntN(10)), 36), 0.10)
	}

	// 页眉：浅色主题是深色横幅配浅字，深色主题是近黑横幅配浅字。
	var headerBg string
	if light {
		headerBg = capLuminance(hexHSL(hue, baseSat+5, 24+float64(r.IntN(8))), 0.04)
	} else {
		headerBg = hexHSL(hue, baseSat, 3+float64(r.IntN(3)))
	}
	headerFg := brightenToContrast(hexHSL(hue, 12, 97), headerBg, minHeaderContrast)

	// accent 是装饰色块/描边：浅色主题里落在浅色底上（必须够深），深色主题里
	// 落在深色底上（必须够亮）。accent_text 是同色系的正文彩色文字，必须与卡片
	// 底色成对比——两者分开是必要的：同一个值无法同时满足"深到能当浅底描边"
	// 和"亮到能当深底文字"。
	var accent, accentText string
	if light {
		accent = capLuminance(hexHSL(hue, baseSat, 36+float64(r.IntN(6))), 0.12)
		accentText = darkenToContrast(hexHSL(hue, baseSat, 38), surface, minTextContrast)
	} else {
		accent = boostLuminance(hexHSL(hue, baseSat, 62+float64(r.IntN(6))), 0.30)
		accentText = brightenToContrast(hexHSL(hue, baseSat, 66), surface, minTextContrast)
	}
	accentDark := darkenToContrast(accent, accent, 1.4)

	// 导航背景：多数主题与页眉同色，低调主题用页面底色。
	navBg := headerBg
	if theme.MinimalNav {
		navBg = surface
	}
	navIsLight := contrastRatio(navBg, "#ffffff") < contrastRatio(navBg, "#000000")
	// 导航链接必须显式按方向生成：浅色导航条上的链接是深色，深色上的是浅色，
	// 让自适应夹紧自己判断容易因亮度阈值落在边界而推到相反的一端。
	var navFg string
	if navIsLight {
		navFg = darkenToContrast(hexHSL(hue, 10, 34), navBg, minTextContrast)
	} else {
		navFg = brightenToContrast(hexHSL(hue, 8, 92), navBg, minTextContrast)
	}
	navFgHover := hoverColor(r, navFg, navBg, navIsLight)

	var heading string
	if light {
		heading = capLuminance(hexHSL(hue, baseSat, 30+float64(r.IntN(6))), 0.09)
	} else {
		heading = boostLuminance(hexHSL(hue, baseSat, 78), 0.58)
	}

	radius := []int{4, 6, 8, 12}[r.IntN(4)]
	maxWidth := []int{680, 700, 720, 760, 800, 840}[r.IntN(6)]
	lineHeight := []string{"1.55", "1.6", "1.65", "1.7"}[r.IntN(4)]
	headingSize := []string{"1.3", "1.4", "1.5", "1.6"}[r.IntN(4)]
	taglineOpacity := []string{"0.82", "0.85", "0.88", "0.9"}[r.IntN(4)]

	return map[string]string{
		"font_body":       fontStacks[r.IntN(len(fontStacks))],
		"bg":              bg,
		"surface":         surface,
		"text":            text,
		"text_muted":      textMuted,
		"border":          border,
		"accent":          accent,
		"accent_dark":     accentDark,
		"accent_text":     accentText,
		"heading_color":   heading,
		"header_bg":       headerBg,
		"header_fg":       headerFg,
		"nav_bg":          navBg,
		"nav_fg":          navFg,
		"nav_fg_hover":    navFgHover,
		"shadow":          hexAlpha(accentDark, []string{"0f", "14", "1a"}[r.IntN(3)]),
		"tagline_opacity": taglineOpacity,
		"radius":          strconv.Itoa(radius),
		"max_width":       strconv.Itoa(maxWidth),
		"line_height":     lineHeight,
		"heading_size":    headingSize,
	}
}

// substituteTokens 用调色板替换主题 CSS 中的 {{token}}。
func substituteTokens(css string, tokens map[string]string) string {
	for name, value := range tokens {
		css = strings.ReplaceAll(css, "{{"+name+"}}", value)
	}
	return css
}

// ---------------------------------------------------------------------------
// 对比度工具
// ---------------------------------------------------------------------------

// 对比度阈值（WCAG 相对亮度比）。
const (
	minTextContrast       = 4.5 // 正文与页脚
	minHeadingContrast    = 3.0 // 大字号标题与 hover 态
	minHeaderContrast     = 3.0 // 页眉横幅上的浅色大字
	minDecorativeContrast = 2.0 // 描边/强调色块等装饰性元素
)

// hexHSL 把 HSL 三元组转成 #rrggbb。h 会归一化到 [0,360)，
// s/l 以百分比传入并夹紧到 [0,100]。
func hexHSL(h, s, l float64) string {
	h = math.Mod(math.Mod(h, 360)+360, 360)
	s = math.Min(math.Max(s, 0), 100) / 100
	l = math.Min(math.Max(l, 0), 100) / 100

	c := (1 - math.Abs(2*l-1)) * s
	x := c * (1 - math.Abs(math.Mod(h/60, 2)-1))
	m := l - c/2

	var r, g, b float64
	switch {
	case h < 60:
		r, g, b = c, x, 0
	case h < 120:
		r, g, b = x, c, 0
	case h < 180:
		r, g, b = 0, c, x
	case h < 240:
		r, g, b = 0, x, c
	case h < 300:
		r, g, b = x, 0, c
	default:
		r, g, b = c, 0, x
	}
	return fmt.Sprintf("#%02x%02x%02x",
		int(math.Round((r+m)*255)), int(math.Round((g+m)*255)), int(math.Round((b+m)*255)))
}

// hexAlpha 给 #rrggbb 追加一个透明度通道（CSS 十六进制记法）。
func hexAlpha(hex, alpha string) string { return hex + alpha }

// parseHex 解析 #rrggbb 或 #rrggbbaa；合法性检查基于前 7 个字符，
// 因此带透明度通道的颜色也能参与亮度计算与明度夹紧。
func parseHex(hex string) (r, g, b int, ok bool) {
	if len(hex) < 7 || hex[0] != '#' {
		return 0, 0, 0, false
	}
	v, err := strconv.ParseUint(hex[1:7], 16, 32)
	if err != nil {
		return 0, 0, 0, false
	}
	return int(v >> 16 & 0xff), int(v >> 8 & 0xff), int(v & 0xff), true
}

// alphaSuffix 返回 #rrggbbaa 的透明度后缀；没有后缀时返回空串。
func alphaSuffix(hex string) string {
	if len(hex) == 9 {
		return hex[7:]
	}
	return ""
}

// relativeLuminance 是 WCAG 2.x 的相对亮度公式。
func relativeLuminance(r, g, b int) float64 {
	lin := func(c int) float64 {
		s := float64(c) / 255
		if s <= 0.03928 {
			return s / 12.92
		}
		return math.Pow((s+0.055)/1.055, 2.4)
	}
	return 0.2126*lin(r) + 0.7152*lin(g) + 0.0722*lin(b)
}

// luminanceOf 返回 #rrggbb 的相对亮度；无法解析时返回 0。
func luminanceOf(hex string) float64 {
	r, g, b, ok := parseHex(hex)
	if !ok {
		return 0
	}
	return relativeLuminance(r, g, b)
}

// contrastRatio 返回两个 #rrggbb 的对比度；任一无法解析时返回 21，
// 使调用方把它当作"已满足"，避免因解析失败而无限夹紧。
func contrastRatio(a, b string) float64 {
	la, lb := luminanceOf(a), luminanceOf(b)
	if la < lb {
		la, lb = lb, la
	}
	return (la + 0.05) / (lb + 0.05)
}

// capLuminance 在保持色相/饱和度的前提下调暗颜色，直到相对亮度不超过 maxLum。
// 用于"必须比背景更深"的元素（正文、标题、浅色底上的描边）。
func capLuminance(hex string, maxLum float64) string {
	return boundLuminance(hex, -2, func(lum float64) bool { return lum <= maxLum })
}

// boostLuminance 与 capLuminance 相反，调亮直到相对亮度不低于 minLum。
// 用于深色主题里的文字与强调色。
func boostLuminance(hex string, minLum float64) string {
	return boundLuminance(hex, 2, func(lum float64) bool { return lum >= minLum })
}

// boundLuminance 以 step 为步长调整明度，直到满足 ok 或逼近明度上下限。
// 相对亮度是单调函数，因此按固定方向迭代必然收敛到最近的可行取值。
func boundLuminance(hex string, step float64, ok func(float64) bool) string {
	r, g, b, valid := parseHex(hex)
	if !valid {
		return hex
	}
	alpha := alphaSuffix(hex)
	h, s, l := rgbToHSL(r, g, b)
	for range 50 {
		candidate := hexHSL(h, s, l)
		if ok(luminanceOf(candidate)) {
			return candidate + alpha
		}
		l += step
		if l < 2 || l > 98 {
			return hexHSL(h, s, math.Min(math.Max(l, 2), 98)) + alpha
		}
	}
	return hexHSL(h, s, math.Min(math.Max(l, 2), 98)) + alpha
}

// rgbToHSL 把已生成的十六进制色转回 HSL，以便在保持色相/饱和度的前提下
// 只调整明度。
func rgbToHSL(r, g, b int) (h, s, l float64) {
	rf, gf, bf := float64(r)/255, float64(g)/255, float64(b)/255
	maxV := math.Max(rf, math.Max(gf, bf))
	minV := math.Min(rf, math.Min(gf, bf))
	l = (maxV + minV) / 2

	delta := maxV - minV
	if delta == 0 {
		return 0, 0, l * 100
	}
	if l > 0.5 {
		s = delta / (2 - maxV - minV)
	} else {
		s = delta / (maxV + minV)
	}
	switch maxV {
	case rf:
		h = math.Mod((gf-bf)/delta, 6)
	case gf:
		h = (bf-rf)/delta + 2
	default:
		h = (rf-gf)/delta + 4
	}
	h *= 60
	if h < 0 {
		h += 360
	}
	return h, s * 100, l * 100
}

// darkenToContrast 在保持色相/饱和度的前提下逐级调暗，直到与 bg 的对比度达标。
// 用于"深色文字/描边落在浅色背景上"的配对。
func darkenToContrast(fg, bg string, minRatio float64) string {
	return adjustToContrast(fg, bg, -2, minRatio)
}

// brightenToContrast 与 darkenToContrast 相反，逐级调亮。
// 用于"浅色文字落在深色背景上"的配对。
func brightenToContrast(fg, bg string, minRatio float64) string {
	return adjustToContrast(fg, bg, 2, minRatio)
}

// adjustToContrast 以 step 为步长朝一个固定方向调整明度，最多 50 步。
// fg 上原有的透明度通道会被保留。
func adjustToContrast(fg, bg string, step, minRatio float64) string {
	bgR, bgG, bgB, bgOK := parseHex(bg)
	return boundLuminance(fg, step, func(lum float64) bool {
		if !bgOK {
			return true
		}
		bgLum := relativeLuminance(bgR, bgG, bgB)
		hi, lo := lum, bgLum
		if hi < lo {
			hi, lo = lo, hi
		}
		return (hi+0.05)/(lo+0.05) >= minRatio
	})
}

// hoverColor 生成导航链接的 hover 颜色：浅色导航条上继续调暗并带一点透明度，
// 深色导航条上调亮到接近白色。
func hoverColor(r *mrand.Rand, navFg, navBg string, navIsLight bool) string {
	if !navIsLight {
		return brightenToContrast(hexHSL(0, 0, 98), navBg, minTextContrast)
	}
	if _, _, _, ok := parseHex(navFg); !ok {
		return navFg
	}
	return adjustToContrast(navFg, navBg, -2, minHeaderContrast) +
		[]string{"", "d9", "cc", "bf"}[r.IntN(4)]
}

// contrastCheck 是一项调色板配色约束的名称、实测值与下限。
type contrastCheck struct {
	Name string
	Got  float64
	Min  float64
}

// validatePalette 返回调色板中全部"文字/背景"配对的实测对比度与下限。
// 它把配色约束集中在一处，只供测试使用：themePalette 的取值本身已按相对亮度
// 窗口生成，这里负责证明"任意一次派生都达标"，而不是在运行时反复校验。
func validatePalette(p map[string]string) []contrastCheck {
	pairs := []struct {
		name     string
		fg, bg   string
		minRatio float64
	}{
		{"text_on_bg", p["text"], p["bg"], minTextContrast},
		{"text_muted_on_bg", p["text_muted"], p["bg"], minTextContrast},
		{"text_muted_on_surface", p["text_muted"], p["surface"], minTextContrast},
		{"heading_on_surface", p["heading_color"], p["surface"], minHeadingContrast},
		{"accent_text_on_surface", p["accent_text"], p["surface"], minTextContrast},
		{"accent_on_bg", p["accent"], p["bg"], minDecorativeContrast},
		{"border_on_bg", p["border"], p["bg"], minDecorativeContrast},
		{"nav_fg_on_nav_bg", p["nav_fg"], p["nav_bg"], minTextContrast},
		{"nav_fg_hover_on_nav_bg", p["nav_fg_hover"], p["nav_bg"], minHeadingContrast},
		{"header_fg_on_header_bg", p["header_fg"], p["header_bg"], minHeaderContrast},
	}

	out := make([]contrastCheck, 0, len(pairs))
	for _, pair := range pairs {
		out = append(out, contrastCheck{
			Name: pair.name,
			Got:  contrastRatio(pair.fg, pair.bg),
			Min:  pair.minRatio,
		})
	}
	return out
}

// ---------------------------------------------------------------------------
// 站点身份
// ---------------------------------------------------------------------------

// siteIdentity 是站点级可见信息。Name 出现在标题栏与页脚，是跨部署最容易
// 被关联的字符串，因此每部署独立生成。
type siteIdentity struct {
	Name string
}

var (
	siteNouns = []string{
		"Ashford", "Brightwater", "Cedar", "Harborview", "Lumen", "Northwind", "Ridgeline",
		"Stonebridge", "Westgate", "Foxglove", "Atlas", "Meridian", "Ironwood", "Kestrel",
		"Beacon", "Cliffside", "Bramble", "Oakfield", "Quarry", "Saltmarsh", "Thorne", "Vantage",
	}
	siteSuffixes = []string{
		"Advisory", "Partners", "Studio", "Group", "Digital", "Consulting", "Systems",
		"Labs", "Collective", "Associates", "Works", "Practice",
	}
	taglines = []string{
		"Innovation delivered with integrity",
		"Rooted in values, growing together",
		"Engineering the future, one line at a time",
		"Wisdom, trust, and the human touch",
		"Crafting clarity through design",
		"Practical thinking for complex work",
		"Measured advice, delivered directly",
		"Building things that last",
		"Experience you can put to work",
		"Clear answers, sensible plans",
		"Small team, serious work",
		"Steady hands for hard problems",
	}
	buildTags = []string{"v2.14.3", "v3.1.0", "v1.9.7", "v4.0.2", "v2.8.11", "v3.4.0"}

	// noticePool 的元素可以包含 {tag} 占位符，由 newFooterNotice 替换成构建号，
	// 使页脚里的统计/构建注释在同一个部署内自洽。
	noticePool = []string{
		"Built with a static site generator {tag}. No tracking scripts are used on this site.",
		"This site sets no cookies and collects no analytics.",
		"Hosted in the EU. Content served from cache where possible.",
		"Accessibility: we aim to meet WCAG 2.2 AA. Tell us if something falls short.",
		"Last reviewed by the editorial team this quarter.",
	}
)

func newSiteIdentity(seed [32]byte) siteIdentity {
	r := gen(seed, "site")
	return siteIdentity{Name: pickRand(r, siteNouns) + " " + pickRand(r, siteSuffixes)}
}

func pickTagline(seed [32]byte) string {
	return pickRand(gen(seed, "tagline"), taglines)
}

func newFooterNotice(seed [32]byte) string {
	notice := pickRand(gen(seed, "notice"), noticePool)
	return strings.ReplaceAll(notice, "{tag}", pickBuildTag(seed))
}

func pickBuildTag(seed [32]byte) string {
	return pickRand(gen(seed, "buildtag"), buildTags)
}

// newLastModified 生成部署级 Last-Modified：在最近 90 天内随机取一个时刻，
// 截断到秒。一个部署内所有页面共用同一个值（真实站点同一批静态文件的 mtime
// 稳定），跨部署不同。
func newLastModified(seed [32]byte) time.Time {
	r := gen(seed, "lastmod")
	offset := time.Duration(r.IntN(90*24*3600)) * time.Second
	return time.Now().Add(-offset).Truncate(time.Second)
}

// analyticsScript 生成页面末尾的一段统计脚本占位。它完全是注释形式，
// 不发起任何外部请求，只是让页面带有真实站点常见的统计/构建痕迹。
func analyticsScript(dep *deployment) string {
	r := gen(dep.seed, "analytics")
	providers := []string{"plausible", "umami", "fathom", "matomo"}
	return fmt.Sprintf("<!-- %s %s -->", pickRand(r, providers), pickBuildTag(dep.seed))
}

// ---------------------------------------------------------------------------
// 导航
// ---------------------------------------------------------------------------

// navCandidates 是 Home 之后可选的导航项。Href 必须落在 detectPageType
// 能识别的路径上，否则页面里会出现指向 404 的死链——真实站点不会这样。
var navCandidates = []navItem{
	{Label: "About", Href: "/about"},
	{Label: "About Us", Href: "/about"},
	{Label: "Company", Href: "/about"},
	{Label: "Services", Href: "/services"},
	{Label: "Solutions", Href: "/services"},
	{Label: "Pricing", Href: "/pricing"},
	{Label: "Blog", Href: "/blog"},
	{Label: "News", Href: "/news"},
	{Label: "Articles", Href: "/articles"},
	{Label: "Contact", Href: "/contact"},
	{Label: "Get in Touch", Href: "/contact"},
	{Label: "Help", Href: "/help"},
}

var homeLabels = []string{"Home", "Start", "Overview"}

// newNavItems 生成 3-4 个导航项：Home 固定在最前，其余从候选中抽取，
// 保证 href 不重复。
func newNavItems(seed [32]byte) []navItem {
	r := gen(seed, "nav")
	items := []navItem{{Label: pickRand(r, homeLabels), Href: "/"}}

	extra := 2 + r.IntN(2) // 2-3 项，合计 3-4 项
	used := map[string]bool{"/": true}
	for range extra {
		for range navCandidates {
			candidate := pickRand(r, navCandidates)
			if used[candidate.Href] {
				continue
			}
			used[candidate.Href] = true
			items = append(items, candidate)
			break
		}
	}
	return items
}
