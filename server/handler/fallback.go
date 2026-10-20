package handler

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"net/http/httputil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/nange/easyss/v3/stats"
)

//go:embed assets/fallback/*.html assets/fallback/*.json
var fallbackFS embed.FS

// 资源已编译进二进制，读取失败属于构建期错误，必须立即暴露出来。
func mustReadFallback(name string) []byte {
	b, err := fallbackFS.ReadFile(name)
	if err != nil {
		panic(fmt.Sprintf("embedded fallback asset %s: %v", name, err))
	}
	return b
}

var fallbackTmpl = template.Must(template.New("fallback").Parse(string(mustReadFallback("assets/fallback/template.html"))))

// CSS 中的 {{token}} 由该部署的种子替换（见 fallback_random.go），同一主题在不同部署里
// 也不相同。
type themeDef struct {
	// 与 assets/fallback/themes.json 的键对应，不会被渲染。
	Name       string
	Mode       string
	MinimalNav bool
	// 未替换的 token 会原样发给扫描器，因此渲染后会做残留断言。
	CSS         template.CSS
	SiteName    string
	Tagline     string
	NavHome     string
	NavAbout    string
	NavServices string
	NavContact  string
}

func loadThemes() []themeDef {
	var themes []themeDef
	if err := json.Unmarshal(mustReadFallback("assets/fallback/themes.json"), &themes); err != nil {
		panic(fmt.Sprintf("embedded fallback asset themes.json: %v", err))
	}
	return themes
}

var themes = loadThemes()

// 路径族决定用哪个子池，拼出来的段落因此始终是同一话题。
type pageContent struct {
	Title      string
	Heading    string
	Paragraphs []string
	Footer     string
}

type legacyPool map[string][]pageContent

type fragmentSet struct {
	Intros   []string
	Bodies   []string
	Extras   []string
	Outros   []string
	Footers  []string
	Titles   []string
	Headings []string
}

type contentPool struct {
	Intros   map[string][]string
	Bodies   map[string][]string
	Extras   map[string][]string
	Outros   map[string][]string
	Footers  map[string][]string
	Titles   map[string][]string
	Headings map[string][]string
	Notices  []string

	Pages legacyPool
}

func loadContentPools() contentPool {
	var pool contentPool
	if err := json.Unmarshal(mustReadFallback("assets/fallback/content.json"), &pool); err != nil {
		panic(fmt.Sprintf("embedded fallback asset content.json: %v", err))
	}
	return pool
}

var contentPools = loadContentPools()

// 缺失的键退化为空池，由 pickRand 的空池守卫兜底。
func (c contentPool) fragments(pageType string) fragmentSet {
	return fragmentSet{
		Intros:   c.Intros[pageType],
		Bodies:   c.Bodies[pageType],
		Extras:   c.Extras[pageType],
		Outros:   c.Outros[pageType],
		Footers:  c.Footers[pageType],
		Titles:   c.Titles[pageType],
		Headings: c.Headings[pageType],
	}
}

type navItem struct {
	Label string
	Href  string
}

type renderData struct {
	CSS          template.CSS
	SiteName     string
	Tagline      string
	NavItems     []navItem
	Title        string
	Description  string
	Heading      string
	Paragraphs   []string
	Footer       string
	FooterNotice string
	BodyClass    string
	HeadExtras   template.HTML
	Analytics    template.HTML
}

// 随机源按 (种子，路径) 域分离派生，同一路径总得到同一页面，缓存溢出后重算也是同样的字节。
func (fb *Fallback) renderPage(path string) []byte {
	dep := fb.dep
	pageType := detectPageType(path)
	content := composeContent(dep, path, pageType)

	data := renderData{
		CSS:          dep.theme.CSS,
		SiteName:     dep.site.Name,
		Tagline:      dep.tagline,
		NavItems:     dep.nav,
		Title:        resolveTitle(content.Title, dep.site.Name),
		Description:  firstParagraph(content.Paragraphs),
		Heading:      content.Heading,
		Paragraphs:   content.Paragraphs,
		Footer:       content.Footer,
		FooterNotice: dep.footerNotice,
		BodyClass:    bodyClass(pageType),
		HeadExtras:   headExtras(dep),
		// 内容来自本包内的固定池或十六进制标记，不含请求数据。
		Analytics: template.HTML(analyticsScript(dep)), //nolint:gosec // 见上
	}

	var buf bytes.Buffer
	if err := fallbackTmpl.Execute(&buf, data); err != nil {
		return []byte("Internal Server Error")
	}
	return buf.Bytes()
}

// 片段池为空时回退到整篇文案，仍然为空时用兜底文案，任何输入都能渲染出页面。
func composeContent(dep *deployment, path, pageType string) pageContent {
	r := gen(dep.seed, "content:"+path)
	f := contentPools.fragments(pageType)

	var paragraphs []string
	if len(f.Intros) > 0 || len(f.Bodies) > 0 {
		introCount := 1
		if len(f.Intros) > 1 {
			introCount += r.IntN(2)
		}
		for i := 0; i < introCount; i++ {
			paragraphs = append(paragraphs, pickRand(r, f.Intros))
		}
		if len(f.Bodies) > 0 {
			bodyCount := 1 + r.IntN(3)
			for range bodyCount {
				paragraphs = append(paragraphs, pickRand(r, f.Bodies))
			}
		}
		if len(f.Extras) > 0 && r.IntN(2) == 0 {
			paragraphs = append(paragraphs, pickRand(r, f.Extras))
		}
		if len(f.Outros) > 0 && r.IntN(3) > 0 {
			paragraphs = append(paragraphs, pickRand(r, f.Outros))
		}
		paragraphs = dedupeParagraphs(paragraphs)
	}

	title := pickRand(r, f.Titles)
	heading := pickRand(r, f.Headings)
	footer := pickRand(r, f.Footers)

	if len(paragraphs) == 0 {
		if legacy := contentPools.Pages[pageType]; len(legacy) > 0 {
			c := legacy[r.IntN(len(legacy))]
			paragraphs = c.Paragraphs
			if title == "" {
				title = c.Title
			}
			if heading == "" {
				heading = c.Heading
			}
			if footer == "" {
				footer = c.Footer
			}
		}
	}

	if len(paragraphs) == 0 {
		paragraphs = []string{"This page is temporarily unavailable. Please try again later."}
	}

	return pageContent{
		Title:      title,
		Heading:    resolveHeading(heading, title),
		Paragraphs: paragraphs,
		Footer:     resolveFooter(dep, footer),
	}
}

func dedupeParagraphs(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, p := range in {
		p = strings.TrimSpace(p)
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}

func resolveHeading(heading, title string) string {
	if h := strings.TrimSpace(heading); h != "" {
		return h
	}
	return strings.TrimSpace(title)
}

// 年份取自本部署的 Last-Modified，页脚版权年份因此与 HTTP 头自洽。
func resolveFooter(dep *deployment, footer string) string {
	footer = strings.TrimSpace(footer)
	footer = strings.ReplaceAll(footer, "{site}", dep.site.Name)
	footer = strings.ReplaceAll(footer, "{year}", strconv.Itoa(dep.lastModified.Year()))
	if footer == "" {
		footer = fmt.Sprintf("© %d %s. All rights reserved.", dep.lastModified.Year(), dep.site.Name)
	}
	return footer
}

// 内容只含本包生成的十六进制标记，以 template.HTML 注入是安全的。
func headExtras(dep *deployment) template.HTML {
	token := hexToken(dep.seed, "asset")
	return template.HTML(fmt.Sprintf(
		`<link rel="icon" href="/favicon-%s.ico">%s<meta name="generator" content="%s">`,
		token, "\n    ", pickBuildTag(dep.seed)))
}

func bodyClass(pageType string) string {
	if pageType == "home" {
		return "home page"
	}
	return "page " + pageType
}

func hexToken(seed [32]byte, purpose string) string {
	r := gen(seed, purpose)
	const alphabet = "0123456789abcdef"
	var b strings.Builder
	for range 8 {
		b.WriteByte(alphabet[r.IntN(len(alphabet))])
	}
	return b.String()
}

// 把客户端可见的原始 Host 和 scheme 传进反向代理的 ModifyResponse，改写 Location 头时
// 不必通过 X-Forwarded-Host 暴露上游。
type ctxKey int

const (
	ctxOrigHost ctxKey = iota
	ctxOrigScheme
	ctxOrigAcceptEncoding
)

// 模式配置与部署级身份在构造完成后只读，可以并发服务请求；运行期唯一的可变状态是
// 有界的生成页缓存（cacheMu 保护）。
type Fallback struct {
	dep *deployment

	custom  []byte
	pages   map[string][]byte
	page404 []byte

	proxy    *httputil.ReverseProxy // nil 表示未启用反代模式
	cdnHosts map[string]bool

	cacheMu    sync.Mutex
	cache      map[string][]byte
	cacheCount int
}

// PreserveHost 与 CDNDomains 只在反向代理模式下生效。
type FallbackConfig struct {
	Target       string
	PreserveHost bool
	CDNDomains   []string
}

type fallbackOptions struct {
	seed  []byte
	theme string
}

type FallbackOption func(*fallbackOptions)

// nil 表示使用 crypto/rand 随机种子。
func WithSeed(seed []byte) FallbackOption {
	return func(o *fallbackOptions) { o.seed = seed }
}

// 主题名不存在时回退为随机选择。
func WithTheme(name string) FallbackOption {
	return func(o *fallbackOptions) { o.theme = name }
}

func NewFallback(cfg FallbackConfig, opts ...FallbackOption) (*Fallback, error) {
	var o fallbackOptions
	for _, opt := range opts {
		opt(&o)
	}
	fb := &Fallback{
		dep:   newDeployment(fallbackVariant{Seed: o.seed, Theme: o.theme}),
		cache: make(map[string][]byte),
	}
	if err := fb.SetTarget(cfg.Target, cfg.PreserveHost, cfg.CDNDomains); err != nil {
		return nil, err
	}
	return fb, nil
}

// 生产路径下只由 builtinFallback 在 sync.Once 内写一次，测试用 setBuiltinFallbackForTest
// 注入固定种子的实例。
var (
	builtinFallbackOnce sync.Once
	builtinFallbackPtr  *Fallback
)

// 供未注入 Fallback 的 handler（例如零值 ProxyHandler）兜底使用，保证一个进程内只诞生
// 一次身份。
func builtinFallback() *Fallback {
	builtinFallbackOnce.Do(func() {
		if builtinFallbackPtr == nil {
			fb, err := NewFallback(FallbackConfig{})
			if err != nil {
				// FallbackConfig{} 只会在内嵌资源损坏时失败，不能静默降级。
				panic(fmt.Sprintf("fallback builtin init: %v", err))
			}
			builtinFallbackPtr = fb
		}
	})
	return builtinFallbackPtr
}

// 必须在没有并发调用 builtinFallback 时调用。
func setBuiltinFallbackForTest(fb *Fallback) {
	builtinFallbackOnce = sync.Once{}
	builtinFallbackPtr = fb
}

const (
	// 达到上限后新路径直接渲染而不缓存，缓存因此不会无限增长。
	maxCachedFallbackPages = 320

	// 之后的路径形如 <host>/<path>，直接拼成 https://<host>/<path> 代理出去。
	cdnPathPrefix = "/__cdn__/"
)

func (fb *Fallback) setHTML(html []byte) {
	if len(html) == 0 {
		return
	}
	fb.custom = make([]byte, len(html))
	copy(fb.custom, html)
}

// 把目录下所有 .html 文件加载为多路由回退页面：404.html 用于未匹配的路径，非 .html 文件
// 被忽略。仅应由构造路径调用。
func (fb *Fallback) setDir(dir string) error {
	pages := make(map[string][]byte)
	var page404 []byte

	err := filepath.WalkDir(dir, func(fpath string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(strings.ToLower(d.Name()), ".html") {
			return nil
		}

		content, err := os.ReadFile(fpath)
		if err != nil {
			return fmt.Errorf("read %s: %w", fpath, err)
		}

		rel, err := filepath.Rel(dir, fpath)
		if err != nil {
			return fmt.Errorf("rel path %s: %w", fpath, err)
		}

		nameWithoutExt := strings.TrimSuffix(d.Name(), ".html")

		if strings.EqualFold(nameWithoutExt, "404") {
			page404 = content
			return nil
		}

		urlPath := "/" + filepath.ToSlash(strings.TrimSuffix(rel, ".html"))

		if strings.EqualFold(nameWithoutExt, "index") {
			if dir := filepath.Dir(rel); dir == "." {
				urlPath = "/"
			} else {
				urlPath = "/" + filepath.ToSlash(dir)
			}
		}

		pages[urlPath] = content
		return nil
	})
	if err != nil {
		return err
	}

	fb.pages = pages
	fb.page404 = page404
	return nil
}

// 按目标字符串选择回退模式：空串为内置生成页，http(s):// 为反向代理，目录为多文件回退，
// 普通文件为单文件自定义 HTML。每次调用先清空全部模式，新配置总是替换而不是叠加。
func (fb *Fallback) SetTarget(target string, preserveHost bool, cdnDomains []string) error {
	fb.proxy = nil
	fb.cdnHosts = nil
	fb.pages = nil
	fb.page404 = nil
	fb.custom = nil

	if target == "" {
		return nil
	}

	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		return fb.setProxy(target, preserveHost, cdnDomains)
	}

	info, err := os.Stat(target)
	if err != nil {
		return fmt.Errorf("stat fallback target: %w", err)
	}

	if info.IsDir() {
		return fb.setDir(target)
	}

	data, err := os.ReadFile(target)
	if err != nil {
		return fmt.Errorf("read fallback target: %w", err)
	}
	fb.setHTML(data)
	return nil
}

// 优先级从高到低：反向代理、目录模式、单文件自定义、自动生成页。
func (fb *Fallback) Serve(w http.ResponseWriter, r *http.Request) {
	stats.RecordServerFallbackPage()

	if fb.proxy != nil {
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		// 剥离 easyss 特有的请求头，上游服务看不到代理协议痕迹。
		r2 := r.Clone(r.Context())
		r2.Header.Del("x-es")
		ctx := context.WithValue(r2.Context(), ctxOrigHost, r2.Host)
		ctx = context.WithValue(ctx, ctxOrigScheme, scheme)
		ctx = context.WithValue(ctx, ctxOrigAcceptEncoding, r2.Header.Get("Accept-Encoding"))
		fb.proxy.ServeHTTP(w, r2.WithContext(ctx))
		return
	}

	path := cleanPath(r.URL.Path)

	// 目录模式的页面完全由运营者提供，状态码与缓存头保持原样。
	if len(fb.pages) > 0 {
		content, ok := fb.pages[path]
		if !ok {
			content = fb.page404
		}
		if !ok && len(content) == 0 {
			content = fb.pages["/"]
		}
		if len(content) > 0 {
			writeRawFallback(w, content)
			return
		}
	}

	if len(fb.custom) > 0 {
		writeRawFallback(w, fb.custom)
		return
	}

	// 自动生成页走完整的 HTTP 真实性层：未知路径返回 404，并补齐 ETag/Last-Modified/条件请求。
	fb.serveGeneratedPage(w, r, path)
}

// 固定 200 与 Content-Type，不注入任何部署级元信息。
func writeRawFallback(w http.ResponseWriter, content []byte) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Server", "nginx")
	w.WriteHeader(http.StatusOK)
	w.Write(content) //nolint:errcheck
}

// 补齐真实静态站点会有的响应头与条件请求语义。
func (fb *Fallback) serveGeneratedPage(w http.ResponseWriter, r *http.Request, path string) {
	body := fb.getOrRenderHTML(path)
	lastModified := fb.dep.lastModified

	if prepareFallbackResponse(w, r, body, lastModified, generatedStatus(r, path)) {
		w.Write(body) //nolint:errcheck
	}
}

// 浏览器式的内容请求（Accept 含 text/html）命中未知路径时返回 404：对随机 URL 一律回 200
// 首页本身就是可观测的伪装特征。非内容请求保持 200，改变响应形状会影响客户端探测降级。
func generatedStatus(r *http.Request, path string) int {
	if detectPageType(path) != "generic" {
		return http.StatusOK
	}
	if strings.Contains(strings.ToLower(r.Header.Get("Accept")), "text/html") {
		return http.StatusNotFound
	}
	return http.StatusOK
}

func (fb *Fallback) getOrRenderHTML(path string) []byte {
	path = cleanPath(path)

	fb.cacheMu.Lock()
	if cached, ok := fb.cache[path]; ok {
		fb.cacheMu.Unlock()
		return cached
	}
	fb.cacheMu.Unlock()

	html := fb.renderPage(path)

	fb.cacheMu.Lock()
	defer fb.cacheMu.Unlock()
	if _, ok := fb.cache[path]; !ok && fb.cacheCount < maxCachedFallbackPages {
		fb.cache[path] = html
		fb.cacheCount++
	}
	return html
}

func cleanPath(p string) string {
	if p == "" || p == "/" {
		return "/"
	}
	return strings.TrimRight(p, "/")
}

func detectPageType(path string) string {
	path = strings.ToLower(strings.Trim(path, "/"))
	switch {
	case path == "":
		return "home"
	case path == "about", strings.HasPrefix(path, "about/"):
		return "about"
	case path == "contact" || path == "support" || strings.HasPrefix(path, "contact/"),
		path == "help":
		return "contact"
	case path == "services" || path == "products" || path == "solutions" ||
		path == "pricing", strings.HasPrefix(path, "services/"),
		strings.HasPrefix(path, "products/"), strings.HasPrefix(path, "solutions/"):
		return "services"
	case path == "blog" || path == "news" || path == "articles" ||
		strings.HasPrefix(path, "blog/") || strings.HasPrefix(path, "news/") ||
		strings.HasPrefix(path, "articles/"):
		return "blog"
	default:
		return "generic"
	}
}

func resolveTitle(title, siteName string) string {
	title = strings.TrimSpace(title)
	if title == "" {
		return siteName
	}
	return title
}

// 首段用作 <meta name="description">。
func firstParagraph(paragraphs []string) string {
	if len(paragraphs) == 0 {
		return ""
	}
	d := paragraphs[0]
	const maxLen = 160
	if len(d) <= maxLen {
		return d
	}
	if i := strings.LastIndex(d[:maxLen], " "); i > 0 {
		return d[:i]
	}
	return d[:maxLen]
}
