package handler

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"html/template"
	"math/rand/v2"
	"net/http"
	"net/http/httputil"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/nange/easyss/v3/log"
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
// 每次部署在启动时随机选择一个主题。
// ---------------------------------------------------------------------------

type themeDef struct {
	// Name 标识资源文件中的主题（见 assets/fallback/themes.json）；该字段不会被渲染。
	Name        string
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
// 内容通过对请求路径做确定性哈希来选取，因此相同的 URL 总是得到相同的内容。
// ---------------------------------------------------------------------------

type pageContent struct {
	Title      string
	Heading    string
	Paragraphs []string
	Footer     string
}

type contentPool map[string][]pageContent

func loadContentPools() contentPool {
	var pools contentPool
	if err := json.Unmarshal(mustReadFallback("assets/fallback/content.json"), &pools); err != nil {
		panic(fmt.Sprintf("embedded fallback asset content.json: %v", err))
	}
	return pools
}

var contentPools = loadContentPools()

// ---------------------------------------------------------------------------
// 渲染用类型
// ---------------------------------------------------------------------------

type renderData struct {
	CSS         template.CSS
	SiteName    string
	Tagline     string
	NavHome     string
	NavAbout    string
	NavServices string
	NavContact  string
	Title       string
	Heading     string
	Paragraphs  []string
	Footer      string
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
	initOnce       sync.Once
	selectedTheme  themeDef
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
	// （/、/about、/contact、/services、/blog 及其别名）只会占用 12 个条目；
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
	initOnce.Do(func() {
		selectedTheme = themes[rand.IntN(len(themes))]
		// 在这里而不是包 init 时记录日志，使记录进入已配置的日志：
		// 部署实际服务的主题，是排查伪装问题时区分两个回退页面的唯一途径。
		log.Debug("[SERVER] fallback theme selected", "theme", selectedTheme.Name)
	})

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

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Server", "nginx")
	w.WriteHeader(http.StatusOK)

	// 优先级 1：基于目录的多文件回退。
	if len(fallbackPages) > 0 {
		content, ok := fallbackPages[cleanPath(r.URL.Path)]
		if !ok {
			content = fallback404
		}
		if !ok && len(content) == 0 {
			// 没有匹配的页面也没有 404.html——回退到 index。
			content = fallbackPages["/"]
		}
		if len(content) > 0 {
			w.Write(content) //nolint:errcheck
			return
		}
	}

	// 优先级 2：单文件自定义回退。
	if len(customFallback) > 0 {
		w.Write(customFallback) //nolint:errcheck
		return
	}

	// 优先级 3：自动生成的主题化页面。
	w.Write(getOrRenderHTML(r.URL.Path)) //nolint:errcheck
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

func getOrRenderHTML(path string) []byte {
	path = cleanPath(path)
	if cached, ok := htmlCache.Load(path); ok {
		return cached.([]byte)
	}

	html := renderHTML(path)
	if htmlCacheCount.Load() < maxCachedFallbackPages {
		if _, loaded := htmlCache.LoadOrStore(path, html); !loaded {
			htmlCacheCount.Add(1)
		}
	}
	return html
}

func renderHTML(path string) []byte {
	pageType := detectPageType(path)
	pool := contentPools[pageType]
	idx := hashIndex(path, len(pool))
	content := pool[idx]

	data := renderData{
		CSS:         selectedTheme.CSS,
		SiteName:    selectedTheme.SiteName,
		Tagline:     selectedTheme.Tagline,
		NavHome:     selectedTheme.NavHome,
		NavAbout:    selectedTheme.NavAbout,
		NavServices: selectedTheme.NavServices,
		NavContact:  selectedTheme.NavContact,
		Title:       resolveTitle(content.Title, selectedTheme.SiteName),
		Heading:     content.Heading,
		Paragraphs:  content.Paragraphs,
		Footer:      content.Footer,
	}

	var buf bytes.Buffer
	if err := fallbackTmpl.Execute(&buf, data); err != nil {
		return []byte("Internal Server Error")
	}
	return buf.Bytes()
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

func hashIndex(input string, n int) int {
	h := fnv.New32a()
	h.Write([]byte(input))
	return int(h.Sum32()) % n
}

// resolveTitle 返回页面标题。如果内容标题为空或只有空白字符，则回退使用站点名称。
func resolveTitle(title, siteName string) string {
	title = strings.TrimSpace(title)
	if title == "" {
		return siteName
	}
	return title
}
