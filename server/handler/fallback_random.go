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
	"time"

	"github.com/nange/easyss/v3/log"
)

// 随机性只落在部署这一层：真实静态站点对同一 URL 返回逐字节相同的内容，每次请求都变
// 反而是更强的自动化指纹。

type deployment struct {
	seed         [32]byte
	theme        themeDef
	site         siteIdentity
	nav          []navItem
	tagline      string
	lastModified time.Time
	footerNotice string
}

// fallbackVariant 生产路径用零值（crypto/rand 生成种子），测试用固定值得到可复现输出。
type fallbackVariant struct {
	Seed  []byte
	Theme string
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

func initialSeed(injected []byte) [32]byte {
	var seed [32]byte
	if len(injected) > 0 {
		if len(injected) == len(seed) {
			copy(seed[:], injected)
			return seed
		}
		return sha256.Sum256(injected)
	}
	if _, err := rand.Read(seed[:]); err != nil {
		// 不能退化成时间戳之类可预测的兜底值，那会把部署级随机降级成可枚举特征。
		panic(fmt.Sprintf("fallback seed: %v", err))
	}
	return seed
}

// 先做域分离再喂给 ChaCha8：新增一个随机消费点不会改变其它用途的输出。
func gen(seed [32]byte, purpose string) *mrand.Rand {
	key := sha256.Sum256(append([]byte(purpose+"\x00"), seed[:]...))
	return mrand.New(mrand.NewChaCha8(key))
}

// 池为空时返回零值而不是 panic：rand.IntN(0) 会 panic，而内容池是可被运维编辑的资源。
func pickRand[T any](r *mrand.Rand, pool []T) T {
	var zero T
	if len(pool) == 0 {
		return zero
	}
	return pool[r.IntN(len(pool))]
}

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

func themePalette(seed [32]byte, theme themeDef) map[string]string {
	r := gen(seed, "palette")

	light := theme.Mode != "dark"
	hue := float64(r.IntN(360))
	baseSat := 30 + float64(r.IntN(26)) // 30-55%
	textSat := float64(r.IntN(12))      // 正文基本中性，避免整页泛色

	// 取值都用相对亮度做窗口约束而不是凭感知明度的经验值：亮度能直接换成对比度。
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

	var headerBg string
	if light {
		headerBg = capLuminance(hexHSL(hue, baseSat+5, 24+float64(r.IntN(8))), 0.04)
	} else {
		headerBg = hexHSL(hue, baseSat, 3+float64(r.IntN(3)))
	}
	headerFg := brightenToContrast(hexHSL(hue, 12, 97), headerBg, minHeaderContrast)

	// accent 用于装饰色块/描边，accent_text 是正文彩色文字，两者必须分开：同一个值
	// 无法同时满足"深到能当浅底描边"和"亮到能当深底文字"。
	var accent, accentText string
	if light {
		accent = capLuminance(hexHSL(hue, baseSat, 36+float64(r.IntN(6))), 0.12)
		accentText = darkenToContrast(hexHSL(hue, baseSat, 38), surface, minTextContrast)
	} else {
		accent = boostLuminance(hexHSL(hue, baseSat, 62+float64(r.IntN(6))), 0.30)
		accentText = brightenToContrast(hexHSL(hue, baseSat, 66), surface, minTextContrast)
	}
	accentDark := darkenToContrast(accent, accent, 1.4)

	navBg := headerBg
	if theme.MinimalNav {
		navBg = surface
	}
	navIsLight := contrastRatio(navBg, "#ffffff") < contrastRatio(navBg, "#000000")
	// 必须显式按方向生成：让自适应夹紧自己判断，容易因亮度阈值落在边界而推到相反一端。
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

func substituteTokens(css string, tokens map[string]string) string {
	for name, value := range tokens {
		css = strings.ReplaceAll(css, "{{"+name+"}}", value)
	}
	return css
}

const (
	minTextContrast       = 4.5
	minHeadingContrast    = 3.0
	minHeaderContrast     = 3.0
	minDecorativeContrast = 2.0
)

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

func hexAlpha(hex, alpha string) string { return hex + alpha }

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

func alphaSuffix(hex string) string {
	if len(hex) == 9 {
		return hex[7:]
	}
	return ""
}

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

func luminanceOf(hex string) float64 {
	r, g, b, ok := parseHex(hex)
	if !ok {
		return 0
	}
	return relativeLuminance(r, g, b)
}

func contrastRatio(a, b string) float64 {
	la, lb := luminanceOf(a), luminanceOf(b)
	if la < lb {
		la, lb = lb, la
	}
	return (la + 0.05) / (lb + 0.05)
}

func capLuminance(hex string, maxLum float64) string {
	return boundLuminance(hex, -2, func(lum float64) bool { return lum <= maxLum })
}

func boostLuminance(hex string, minLum float64) string {
	return boundLuminance(hex, 2, func(lum float64) bool { return lum >= minLum })
}

// 相对亮度是单调函数，按固定方向迭代必然收敛到最近的可行取值。
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

func darkenToContrast(fg, bg string, minRatio float64) string {
	return adjustToContrast(fg, bg, -2, minRatio)
}

func brightenToContrast(fg, bg string, minRatio float64) string {
	return adjustToContrast(fg, bg, 2, minRatio)
}

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

type contrastCheck struct {
	Name string
	Got  float64
	Min  float64
}

// validatePalette 只供测试使用，证明任意一次派生都达标。
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

// Name 出现在标题栏与页脚，是跨部署最容易被关联的字符串，因此每部署独立生成。
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

	// 元素可含 {tag} 占位符，由 newFooterNotice 替换成构建号。
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

// 一个部署内所有页面共用同一个 Last-Modified（真实站点同一批静态文件的 mtime 稳定）。
func newLastModified(seed [32]byte) time.Time {
	r := gen(seed, "lastmod")
	offset := time.Duration(r.IntN(90*24*3600)) * time.Second
	return time.Now().Add(-offset).Truncate(time.Second)
}

// 完全是注释形式，不发起任何外部请求，只让页面带有真实站点常见的统计/构建痕迹。
func analyticsScript(dep *deployment) string {
	r := gen(dep.seed, "analytics")
	providers := []string{"plausible", "umami", "fathom", "matomo"}
	return fmt.Sprintf("<!-- %s %s -->", pickRand(r, providers), pickBuildTag(dep.seed))
}

// Href 必须落在 detectPageType 能识别的路径上，否则页面里会出现指向 404 的死链。
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

// Home 固定在最前，其余从候选中抽取且 href 不重复。
func newNavItems(seed [32]byte) []navItem {
	r := gen(seed, "nav")
	items := []navItem{{Label: pickRand(r, homeLabels), Href: "/"}}

	extra := 2 + r.IntN(2) // 合计 3-4 项
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
