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
	"sync/atomic"

	"github.com/nange/easyss/v3/stats"
)

// fallbackFS 内嵌主题页面模板、主题定义和内容池（见 assets/fallback）。
// 把它们放在 Go 源码之外，可以在不改动代码的情况下调整页面；它们会被编译进
// 二进制，因此缺失或损坏的资源会在启动时立刻暴露，而不是等到请求时才出错。
//
//go:embed assets/fallback/*.html assets/fallback/*.json
var fallbackFS embed.FS

// mustReadFallback 读取内嵌资源，失败时直接 panic：资源已编译进二进制，
// 文件缺失属于构建期错误，必须立即暴露出来。
func mustReadFallback(name string) []byte {
	b, err := fallbackFS.ReadFile(name)
	if err != nil {
		panic(fmt.Sprintf("embedded fallback asset %s: %v", name, err))
	}
	return b
}

var fallbackTmpl = template.Must(template.New("fallback").Parse(string(mustReadFallback("assets/fallback/template.html"))))

// ---------------------------------------------------------------------------
// 主题定义——每个主题包含 CSS 和站点级信息。
// 各主题在视觉上彼此不同：不同的配色、字体和布局参数。
// 每次部署在启动时随机选择一个主题，并用该部署的种子替换 CSS 中的 {{token}}
// 占位符（见 fallback_random.go），因此同一主题在不同部署里也不相同。
// ---------------------------------------------------------------------------

type themeDef struct {
	// Name 标识资源文件中的主题（见 assets/fallback/themes.json）；该字段不会被渲染。
	Name string
	// Mode 是 "light" 或 "dark"，决定调色板派生的明度分档。
	Mode string
	// MinimalNav 为真时导航背景使用页面底色而不是页眉底色（低调排版主题）。
	MinimalNav bool
	// CSS 中允许出现 {{token}} 占位符，由 themePalette 在启动时替换为随机值。
	// 未被替换的 token 会原样发给扫描器，因此渲染后会做残留断言。
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

// ---------------------------------------------------------------------------
// 内容池——每种页面类型对应的真实、多样的文本。
//
// 页面由三段拼装而成：intros + bodies(+extras) + outros，标题与一级标题从
// titles/headings 池中独立抽取，页脚从 footers 池中抽取。路径族决定使用哪个
// 子池，因此拼出来的段落始终是同一话题，读起来是一篇连贯的页面。
//
// 旧式的"每种页面类型一整篇"内容（legacyPool）仍然支持：只提供整篇文案的
// 部署不会因此出问题。
// ---------------------------------------------------------------------------

type pageContent struct {
	Title      string
	Heading    string
	Paragraphs []string
	Footer     string
}

// legacyPool 是每种页面类型下的整篇页面文案。
type legacyPool map[string][]pageContent

// fragmentSet 是同一路径族下可自由组合的片段池。
type fragmentSet struct {
	Intros   []string
	Bodies   []string
	Extras   []string
	Outros   []string
	Footers  []string
	Titles   []string
	Headings []string
}

// contentPool 是 content.json 解析后的全部内容资源。
type contentPool struct {
	Intros   map[string][]string
	Bodies   map[string][]string
	Extras   map[string][]string
	Outros   map[string][]string
	Footers  map[string][]string
	Titles   map[string][]string
	Headings map[string][]string
	Notices  []string

	// Pages 保存旧式整篇文案，键是页面类型。
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

// fragments 返回某个页面类型的片段池。缺失的键一律退化为空池，
// 由 pickRand 的空池守卫兜底，不会 panic。
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

// ---------------------------------------------------------------------------
// 渲染用类型
// ---------------------------------------------------------------------------

// navItem 是渲染后的一个导航链接。
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

// ---------------------------------------------------------------------------
// 渲染
// ---------------------------------------------------------------------------

// renderPage 为一个路径渲染完整页面。随机源按 (种子, 路径) 域分离派生，
// 因此同一路径总是得到同一页面（真实静态站的行为），htmlCache 溢出后
// 重算也得到同样的字节。
func renderPage(path string) []byte {
	dep := currentDeployment()
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
		// 统计注释、构建号与图标名都来自本包内的固定池或十六进制标记，
		// 不含任何请求数据，因此可以直接注入。
		Analytics: template.HTML(analyticsScript(dep)), //nolint:gosec // 见上
	}

	var buf bytes.Buffer
	if err := fallbackTmpl.Execute(&buf, data); err != nil {
		return []byte("Internal Server Error")
	}
	return buf.Bytes()
}

// composeContent 为路径拼装页面内容。优先使用片段池；片段池为空时回退到
// 旧式整篇文案；仍然为空时用兜底文案，保证任何输入都能渲染出页面。
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

	// 片段池为空：退回旧式整篇文案。
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
		// 最后的兜底：任何内容资源损坏的情况下页面仍然是完整可读的。
		paragraphs = []string{"This page is temporarily unavailable. Please try again later."}
	}

	return pageContent{
		Title:      title,
		Heading:    resolveHeading(heading, title),
		Paragraphs: paragraphs,
		Footer:     resolveFooter(dep, footer),
	}
}

// dedupeParagraphs 去掉拼装过程中可能重复的段落，保持原有顺序。
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

// resolveHeading 返回一级标题；为空时退回页面标题。
func resolveHeading(heading, title string) string {
	if h := strings.TrimSpace(heading); h != "" {
		return h
	}
	return strings.TrimSpace(title)
}

// resolveFooter 替换页脚里的 {site} 与 {year} 占位符。年份取自本部署的
// Last-Modified，使页脚版权年份与 HTTP 头自洽。
func resolveFooter(dep *deployment, footer string) string {
	footer = strings.TrimSpace(footer)
	footer = strings.ReplaceAll(footer, "{site}", dep.site.Name)
	footer = strings.ReplaceAll(footer, "{year}", strconv.Itoa(dep.lastModified.Year()))
	if footer == "" {
		footer = fmt.Sprintf("© %d %s. All rights reserved.", dep.lastModified.Year(), dep.site.Name)
	}
	return footer
}

// headExtras 生成 <head> 中的可选内容。内容由本包生成，只包含十六进制标记，
// 因此以 template.HTML 注入是安全的（html/template 不会转义它）。
func headExtras(dep *deployment) template.HTML {
	token := hexToken(dep.seed, "asset")
	return template.HTML(fmt.Sprintf(
		`<link rel="icon" href="/favicon-%s.ico">%s<meta name="generator" content="%s">`,
		token, "\n    ", pickBuildTag(dep.seed)))
}

// bodyClass 为 <body> 生成一个看似由主题/模板生成的 class。
func bodyClass(pageType string) string {
	if pageType == "home" {
		return "home page"
	}
	return "page " + pageType
}

// hexToken 派生一个短十六进制标记，用作资源文件名的构建指纹。
func hexToken(seed [32]byte, purpose string) string {
	r := gen(seed, purpose)
	const alphabet = "0123456789abcdef"
	var b strings.Builder
	for range 8 {
		b.WriteByte(alphabet[r.IntN(len(alphabet))])
	}
	return b.String()
}

// ---------------------------------------------------------------------------
// 全局状态
// ---------------------------------------------------------------------------

// ctxKey 是一个未导出的 context 键类型，用于把客户端可见的原始 Host 和 scheme
// 从 ServeFallback 传入反向代理的 ModifyResponse 钩子，从而可以把指向上游主机
// 的 Location 头重写回客户端可见的主机，而无需通过 X-Forwarded-Host 暴露上游。
type ctxKey int

const (
	ctxOrigHost ctxKey = iota
	ctxOrigScheme
	ctxOrigAcceptEncoding
)

var (
	customFallback []byte
	htmlCache      sync.Map // path string → []byte（路径到页面字节）
	htmlCacheCount atomic.Int32

	// 基于目录的多文件回退。
	fallbackPages map[string][]byte // path → HTML 字节（如 "/about" → <html>...）
	fallback404   []byte            // 可选的 404 页面

	// 指向上游 HTTP 服务（如本地 nginx）的反向代理。
	fallbackProxy *httputil.ReverseProxy

	// /__cdn__/<host>/... 路径前缀路由所允许的 CDN 主机集合。
	// 由 setFallbackProxy 根据 cdnDomains 配置填充。键为小写主机名；
	// 仅当 "github.githubassets.com" 在该集合中时，对
	// /__cdn__/github.githubassets.com/x 的请求才会被代理。
	fallbackCDNHosts map[string]bool
)

const (
	// maxCachedFallbackPages 限制生成页面的缓存规模。固定的关键字路径
	// （/、/about、/contact、/services、/blog 及其别名）只会占用少量条目；
	// 其余预算用于任意（generic）路径，这样扫描器命中随机 URL 时
	// 不会每次请求都触发模板渲染。达到上限后，新的不同路径直接渲染而不缓存
	// （一次渲染只是一次小规模模板执行），因此缓存不会无限增长。
	maxCachedFallbackPages = 320

	// cdnPathPrefix 是配置的 CDN 域请求所路由到的 URL 路径前缀。请求
	//   /__cdn__/github.githubassets.com/assets/foo.css
	// 会被代理到
	//   https://github.githubassets.com/assets/foo.css
	cdnPathPrefix = "/__cdn__/"
)

// setFallbackHTML 用自定义 HTML 覆盖内置的回退系统。
// 必须在服务器开始接受请求之前调用。
func setFallbackHTML(html []byte) {
	if len(html) == 0 {
		return
	}
	customFallback = make([]byte, len(html))
	copy(customFallback, html)
}

// setFallbackDir 把目录下所有 .html 文件加载为多路由回退页面。文件到路径的映射：
//   - index.html         → "/"
//   - 404.html           → 未匹配的路径
//   - <name>.html        → "/<name>"
//   - <sub>/<name>.html  → "/<sub>/<name>"
//   - <sub>/index.html   → "/<sub>"
//
// 非 .html 文件会被忽略。必须在服务器开始接受请求之前调用。
func setFallbackDir(dir string) error {
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

		// 404.html 是特殊的：作为未匹配路径的页面存储，而不是普通页面。
		if strings.EqualFold(nameWithoutExt, "404") {
			page404 = content
			return nil
		}

		// 根据相对文件路径构建 URL 路径。
		urlPath := "/" + filepath.ToSlash(strings.TrimSuffix(rel, ".html"))

		// index.html 映射到父目录（根目录时为 "/"）。
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

	fallbackPages = pages
	fallback404 = page404
	return nil
}

// SetFallbackTarget 解析单个回退目标字符串并配置相应的回退模式。目标字符串按如下解释：
//   - ""                           → 内置的主题化自动生成页面
//   - "http://..." / "https://..." → 指向上游 HTTP 服务的反向代理
//   - 目录路径                       → 多文件 HTML 回退（setFallbackDir）
//   - 普通文件路径                    → 单文件自定义 HTML（setFallbackHTML）
//
// preserveHost 和 cdnDomains 只影响反向代理模式（见 setFallbackProxy）；
// 在目录/文件/内置模式下会被忽略。
func SetFallbackTarget(target string, preserveHost bool, cdnDomains []string) error {
	// 重置所有回退状态。
	fallbackProxy = nil
	fallbackCDNHosts = nil
	fallbackPages = nil
	fallback404 = nil
	customFallback = nil

	if target == "" {
		return nil
	}

	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		return setFallbackProxy(target, preserveHost, cdnDomains)
	}

	info, err := os.Stat(target)
	if err != nil {
		return fmt.Errorf("stat fallback target: %w", err)
	}

	if info.IsDir() {
		return setFallbackDir(target)
	}

	data, err := os.ReadFile(target)
	if err != nil {
		return fmt.Errorf("read fallback target: %w", err)
	}
	setFallbackHTML(data)
	return nil
}

// ServeFallback 向响应写入一个回退 HTML 页面。
// 优先级（从高到低）：
//  0. 指向上游 HTTP 服务的反向代理（setFallbackProxy）
//  1. 基于目录的多文件回退（setFallbackDir）
//  2. 单文件自定义回退（setFallbackHTML）
//  3. 自动生成的主题化页面
func ServeFallback(w http.ResponseWriter, r *http.Request) {
	stats.RecordServerFallbackPage()

	// 优先级 0（最高）：指向上游 HTTP 服务的反向代理。
	if fallbackProxy != nil {
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		// 转发前剥离 easyss 特有的请求头（如 x-es），使上游服务永远看不到代理协议痕迹。
		r2 := r.Clone(r.Context())
		r2.Header.Del("x-es")
		ctx := context.WithValue(r2.Context(), ctxOrigHost, r2.Host)
		ctx = context.WithValue(ctx, ctxOrigScheme, scheme)
		ctx = context.WithValue(ctx, ctxOrigAcceptEncoding, r2.Header.Get("Accept-Encoding"))
		fallbackProxy.ServeHTTP(w, r2.WithContext(ctx))
		return
	}

	path := cleanPath(r.URL.Path)

	// 优先级 1：基于目录的多文件回退。这些页面完全由运营者提供，
	// 因此状态码与缓存头保持原样（200 + 固定的 Content-Type）。
	if len(fallbackPages) > 0 {
		content, ok := fallbackPages[path]
		if !ok {
			content = fallback404
		}
		if !ok && len(content) == 0 {
			// 没有匹配的页面也没有 404.html——回退到 index。
			content = fallbackPages["/"]
		}
		if len(content) > 0 {
			writeRawFallback(w, content)
			return
		}
	}

	// 优先级 2：单文件自定义回退。
	if len(customFallback) > 0 {
		writeRawFallback(w, customFallback)
		return
	}

	// 优先级 3：自动生成的主题化页面。这里走完整的 HTTP 真实性层：
	// 未知路径返回 404，并补齐 ETag/Last-Modified/条件请求。
	serveGeneratedPage(w, r, path)
}

// writeRawFallback 写出运营者提供的回退页面。保持此前的行为：
// 固定 200、固定 Content-Type，不注入任何部署级元信息。
func writeRawFallback(w http.ResponseWriter, content []byte) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Server", "nginx")
	w.WriteHeader(http.StatusOK)
	w.Write(content) //nolint:errcheck
}

// serveGeneratedPage 服务自动生成的页面，并补齐真实静态站点会有的响应头与
// 条件请求语义。
func serveGeneratedPage(w http.ResponseWriter, r *http.Request, path string) {
	body := getOrRenderHTML(path)
	lastModified := currentDeployment().lastModified

	if prepareFallbackResponse(w, r, body, lastModified, generatedStatus(r, path)) {
		w.Write(body) //nolint:errcheck
	}
}

// generatedStatus 决定自动生成页面的状态码。
//
// 浏览器式的内容请求（Accept 中含 text/html）命中未知路径时返回 404：
// 对随机 URL 一律回 200 首页本身就是可观测的伪装特征，真实站点会 404。
//
// 非内容请求（例如 easyss 客户端对 /v3/probe 的主动探测，Accept 为 */*）
// 保持 200 + 页面正文：那里没有任何指纹收益，而保持响应形状不变可以避免
// 影响既有客户端与探测降级逻辑。
func generatedStatus(r *http.Request, path string) int {
	if detectPageType(path) != "generic" {
		return http.StatusOK
	}
	if strings.Contains(strings.ToLower(r.Header.Get("Accept")), "text/html") {
		return http.StatusNotFound
	}
	return http.StatusOK
}

// getOrRenderHTML 返回路径对应的页面字节，命中缓存时直接复用。
func getOrRenderHTML(path string) []byte {
	path = cleanPath(path)
	if cached, ok := htmlCache.Load(path); ok {
		return cached.([]byte)
	}

	html := renderPage(path)
	if htmlCacheCount.Load() < maxCachedFallbackPages {
		if _, loaded := htmlCache.LoadOrStore(path, html); !loaded {
			htmlCacheCount.Add(1)
		}
	}
	return html
}

// cleanPath 规范化用于查找的 URL 路径："/" 保持 "/" 不变，其余路径去除末尾的斜杠。
func cleanPath(p string) string {
	if p == "" || p == "/" {
		return "/"
	}
	return strings.TrimRight(p, "/")
}

// ---------------------------------------------------------------------------
// 内部辅助函数
// ---------------------------------------------------------------------------

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

// resolveTitle 返回页面标题。如果内容标题为空或只有空白字符，则回退使用站点名称。
func resolveTitle(title, siteName string) string {
	title = strings.TrimSpace(title)
	if title == "" {
		return siteName
	}
	return title
}

// firstParagraph 返回首段，用作 <meta name="description">；没有段落时返回空串。
func firstParagraph(paragraphs []string) string {
	if len(paragraphs) == 0 {
		return ""
	}
	d := paragraphs[0]
	const maxLen = 160
	if len(d) <= maxLen {
		return d
	}
	// 截断到最后一个空格，避免把单词切一半。
	if i := strings.LastIndex(d[:maxLen], " "); i > 0 {
		return d[:i]
	}
	return d[:maxLen]
}
