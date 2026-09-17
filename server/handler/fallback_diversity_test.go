package handler

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	sharedconfig "github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/crypto"
)

// ---------------------------------------------------------------------------
// 部署级随机化
// ---------------------------------------------------------------------------

// withDeployment 用固定种子/主题重建部署级身份，并在测试结束后把包状态恢复到
// 自动初始化，避免污染同一包内的其它测试。
func withDeployment(t *testing.T, seed []byte, theme string) *deployment {
	t.Helper()
	depOnce = sync.Once{}
	depState = nil
	htmlCache = sync.Map{}
	htmlCacheCount.Store(0)
	initFallback(fallbackVariant{Seed: seed, Theme: theme})
	t.Cleanup(func() {
		depOnce = sync.Once{}
		depState = nil
		htmlCache = sync.Map{}
		htmlCacheCount.Store(0)
	})
	return depState
}

func seedOf(n int) []byte {
	s := seed32(n)
	return s[:]
}

// seed32 与 seedOf 同源，供需要固定 [32]byte 的函数使用。
func seed32(n int) [32]byte {
	return sha256.Sum256([]byte(fmt.Sprintf("test-seed-%d", n)))
}

// TestInitFallback_Deterministic 验证同一种子得到逐字节相同的页面与响应头。
func TestInitFallback_Deterministic(t *testing.T) {
	first := renderAll(t, seedOf(1))
	second := renderAll(t, seedOf(1))

	for path, body := range first {
		if !bytes.Equal(second[path], body) {
			t.Errorf("path %q: same seed produced different bytes", path)
		}
	}
}

// TestInitFallback_Idempotent 验证重复初始化只生效一次。
func TestInitFallback_Idempotent(t *testing.T) {
	dep := withDeployment(t, seedOf(2), "")
	before := dep.site.Name

	// 第二次调用（同一种子）必须是无操作。
	initFallback(fallbackVariant{Seed: seedOf(3)})
	if got := depState.site.Name; got != before {
		t.Errorf("second init changed deployment identity: %q -> %q", before, got)
	}
}

// TestInitFallback_ConcurrentInit 验证并发初始化在 -race 下不产生数据竞争。
func TestInitFallback_ConcurrentInit(t *testing.T) {
	depOnce = sync.Once{}
	depState = nil
	t.Cleanup(func() {
		depOnce = sync.Once{}
		depState = nil
	})

	var wg sync.WaitGroup
	for range 50 {
		wg.Go(func() { initFallback(fallbackVariant{}) })
	}
	wg.Wait()

	if depState == nil {
		t.Fatal("deployment not initialized")
	}
}

// TestInitFallback_DifferentSeedsDiffer 覆盖成功标准 1：不同部署的首页字节
// 差异率必须足够高，并且站点名、Last-Modified 都要不同。
func TestInitFallback_DifferentSeedsDiffer(t *testing.T) {
	a := renderAll(t, seedOf(10))
	depA := depState.site.Name
	modA := depState.lastModified

	b := renderAll(t, seedOf(11))

	bodyA, bodyB := a["/"], b["/"]
	if bytes.Equal(bodyA, bodyB) {
		t.Fatal("two seeds produced identical home pages")
	}
	if depA == depState.site.Name {
		t.Errorf("two seeds produced the same site name %q", depA)
	}
	if modA.Equal(depState.lastModified) {
		t.Error("two seeds produced the same Last-Modified")
	}

	diff := byteDiffRatio(bodyA, bodyB)
	if diff < 0.30 {
		t.Errorf("home page byte difference ratio = %.3f, want >= 0.30", diff)
	}
}

// TestInitFallback_DeploymentSpace 验证随机化空间：50 个种子应产生接近 50 个
// 互不相同的调色板与首页。
func TestInitFallback_DeploymentSpace(t *testing.T) {
	palettes := make(map[string]int)
	homes := make(map[string]int)
	for i := range 50 {
		withDeployment(t, seedOf(100+i), "")
		palettes[strongETag([]byte(depState.theme.CSS))]++
		homes[strongETag(renderPage("/"))]++
	}

	if distinct := len(palettes); distinct < 45 {
		t.Errorf("only %d distinct palettes out of 50 seeds", distinct)
	}
	if distinct := len(homes); distinct < 50 {
		t.Errorf("only %d distinct home pages out of 50 seeds", distinct)
	}
}

// TestVisibleCombinationSpace 覆盖成功标准 2：首页可见组合空间必须远大于改造前
// 的 5 主题 × 5 文案 = 25。
//
// 组合空间（跨部署）=
//
//	色相 × 饱和度 × 半径 × 卡片宽度 × 行高 × 标题字号 × tagline 透明度 × 字体栈
//	× 站点名 × tagline × 导航组合 × 标题 × 一级标题 × 正文段落组合
//
// 用各池实际规模相乘得到下界，而不是靠估数：任何一个池被改小都会让这条断言失败。
func TestVisibleCombinationSpace(t *testing.T) {
	withDeployment(t, seedOf(900), "")

	// 主题内部的连续/离散参数（themePalette 的取值域）。
	const (
		hues        = 360 // 基准色相
		saturations = 26  // 30-55%
		radii       = 4
		widths      = 6
		lineHeights = 4
		headSizes   = 4
		opacities   = 4
		textSats    = 12
	)
	themesN := len(themes)
	fonts := len(fontStacks)
	siteNames := len(siteNouns) * len(siteSuffixes)
	taglinesN := len(taglines)
	navSpace := combinationCount(len(navCandidates), 2) + combinationCount(len(navCandidates), 3)

	frag := contentPools.fragments("home")
	contentSpace := len(frag.Titles) * len(frag.Headings) * len(frag.Intros) *
		len(frag.Bodies) * (len(frag.Extras) + 1)

	space := hues * saturations * radii * widths * lineHeights * headSizes * opacities *
		textSats * themesN * fonts * siteNames * taglinesN * navSpace * contentSpace

	t.Logf("visible combination space = %.3g (themes=%d fonts=%d siteNames=%d nav=%d content=%d)",
		float64(space), themesN, fonts, siteNames, navSpace, contentSpace)

	const wantSpace = 1_000_000
	if space < wantSpace {
		t.Errorf("visible combination space = %d, want >= %d", space, wantSpace)
	}
	// 站点名的规模必须远大于原先固定 5 个标题名。
	if siteNames < 100 {
		t.Errorf("site name space = %d, want >= 100", siteNames)
	}
}

// combinationCount 返回 C(n, k)；k > n 时为 0。
func combinationCount(n, k int) int {
	if k > n {
		return 0
	}
	result := 1
	for i := range k {
		result = result * (n - i) / (i + 1)
	}
	return result
}

// TestNewSiteIdentity_PoolCoverage 验证站点名取自组合池而不是固定值。
func TestNewSiteIdentity_PoolCoverage(t *testing.T) {
	names := make(map[string]bool)
	for i := range 200 {
		names[newSiteIdentity(seed32(200+i)).Name] = true
	}
	if len(names) < 100 {
		t.Errorf("only %d distinct site names out of 200 seeds", len(names))
	}
}

// ---------------------------------------------------------------------------
// 主题与调色板
// ---------------------------------------------------------------------------

// placeholderRe 匹配未替换的 {{token}} 占位符。
var placeholderRe = regexp.MustCompile(`\{\{\w+\}\}`)

// TestThemeCSSTokensResolved 覆盖"任何一次派生都不把占位符发给扫描器"。
func TestThemeCSSTokensResolved(t *testing.T) {
	for i := range 20 {
		withDeployment(t, seedOf(300+i), "")

		css := string(depState.theme.CSS)
		if m := placeholderRe.FindString(css); m != "" {
			t.Fatalf("seed %d: unreplaced token %s in theme CSS", i, m)
		}
		if strings.Contains(css, "{{") || strings.Contains(css, "}}") {
			t.Fatalf("seed %d: leftover braces in theme CSS", i)
		}
		// 调色板不允许留有任何硬编码的色值。
		if strings.Contains(css, "#") && strings.Contains(css, "{{") {
			t.Fatalf("seed %d: mixed tokens and literals", i)
		}
	}
}

// TestThemeCSS_Contrast 验证任意一次派生都得到可读配色，而不是随机撞色。
// 这里直接校验调色板本身：主题 CSS 里的 token 已被替换，无法再用于配对。
func TestThemeCSS_Contrast(t *testing.T) {
	for i := range 40 {
		withDeployment(t, seedOf(400+i), "")
		for _, check := range validatePalette(themePalette(depState.seed, depState.theme)) {
			if check.Got < check.Min-0.01 {
				t.Errorf("seed %d: %s contrast = %.2f, want >= %.2f",
					i, check.Name, check.Got, check.Min)
			}
		}
	}
}

// TestThemesJSON_TokenWhitelist 保证资源文件里不会出现拼错的 token：
// 一旦拼错，它会原样出现在发给扫描器的 CSS 里。
func TestThemesJSON_TokenWhitelist(t *testing.T) {
	allowed := map[string]bool{
		"font_body": true, "bg": true, "surface": true, "text": true, "text_muted": true,
		"border": true, "accent": true, "accent_dark": true, "accent_text": true,
		"heading_color": true, "header_bg": true, "header_fg": true, "nav_bg": true,
		"nav_fg": true, "nav_fg_hover": true, "shadow": true, "tagline_opacity": true,
		"radius": true, "max_width": true, "line_height": true, "heading_size": true,
	}

	tokenRe := regexp.MustCompile(`\{\{(\w+)\}\}`)
	seen := make(map[string]bool)
	for _, theme := range themes {
		for _, m := range tokenRe.FindAllStringSubmatch(string(theme.CSS), -1) {
			if !allowed[m[1]] {
				t.Errorf("theme %q: unknown CSS token %q", theme.Name, m[1])
			}
			seen[m[1]] = true
		}
	}
	// 每个允许的 token 都应至少被一个主题用到，否则是死 token。
	for name := range allowed {
		if !seen[name] {
			t.Errorf("token %q is declared but never used in themes.json", name)
		}
	}
	for _, theme := range themes {
		if theme.Mode != "light" && theme.Mode != "dark" {
			t.Errorf("theme %q: Mode = %q, want light|dark", theme.Name, theme.Mode)
		}
	}
}

// ---------------------------------------------------------------------------
// 内容组合
// ---------------------------------------------------------------------------

// TestComposeContent_Shape 验证拼装出的页面结构合理：3-5 段、标题/一级标题
// 非空、页脚含站点名与年份。
func TestComposeContent_Shape(t *testing.T) {
	withDeployment(t, seedOf(500), "")

	for _, path := range []string{"/", "/about", "/services", "/blog", "/contact", "/random"} {
		content := composeContent(depState, path, detectPageType(path))
		if n := len(content.Paragraphs); n < 2 || n > 6 {
			t.Errorf("path %q: %d paragraphs, want 2-6", path, n)
		}
		if strings.TrimSpace(content.Heading) == "" {
			t.Errorf("path %q: empty heading", path)
		}
		if strings.TrimSpace(content.Footer) == "" {
			t.Errorf("path %q: empty footer", path)
		}
		// 页脚的 {site}/{year} 占位符必须都已解析，否则会把字面占位符发给扫描器。
		if strings.ContainsAny(content.Footer, "{}") {
			t.Errorf("path %q: footer %q has unresolved placeholders", path, content.Footer)
		}
		for _, p := range content.Paragraphs {
			if strings.TrimSpace(p) == "" {
				t.Errorf("path %q: empty paragraph", path)
			}
		}
	}
}

// TestComposeContent_EmptyPools 验证资源文件缺字段时不 panic：
// rand.IntN(0) 会 panic，因此空池必须有守卫。
func TestComposeContent_EmptyPools(t *testing.T) {
	withDeployment(t, seedOf(501), "")

	saved := contentPools
	contentPools = contentPool{}
	t.Cleanup(func() { contentPools = saved })

	content := composeContent(depState, "/", "home")
	if len(content.Paragraphs) == 0 {
		t.Error("empty pools should still produce a fallback paragraph")
	}
	if strings.TrimSpace(content.Footer) == "" {
		t.Error("empty pools should still produce a footer")
	}

	for i := range 10 {
		_ = pickRand(gen(seed32(i), "empty"), []string(nil))
		_ = pickRand(gen(seed32(i), "empty"), []int{})
	}
}

// TestLegacyContentPool 验证旧式"整篇文案"格式（只有 <pageType> 数组、
// 没有片段池）仍然可以渲染出页面。
func TestLegacyContentPool(t *testing.T) {
	withDeployment(t, seedOf(502), "")

	saved := contentPools
	contentPools = contentPool{Pages: legacyPool{
		"home": {{Title: "Legacy Home", Heading: "Legacy Heading", Paragraphs: []string{"Legacy paragraph."}}},
	}}
	t.Cleanup(func() { contentPools = saved })

	content := composeContent(depState, "/", "home")
	if content.Heading != "Legacy Heading" {
		t.Errorf("legacy heading = %q", content.Heading)
	}
	if len(content.Paragraphs) != 1 || content.Paragraphs[0] != "Legacy paragraph." {
		t.Errorf("legacy paragraphs = %v", content.Paragraphs)
	}
}

// ---------------------------------------------------------------------------
// 导航
// ---------------------------------------------------------------------------

// TestNavItems_LinksResolve 验证导航里不会出现死链：每个 href 都必须能被
// detectPageType 归入一个真实存在的页面族。
func TestNavItems_LinksResolve(t *testing.T) {
	for i := range 50 {
		withDeployment(t, seedOf(600+i), "")
		nav := depState.nav

		if len(nav) < 3 || len(nav) > 4 {
			t.Fatalf("seed %d: %d nav items, want 3-4", i, len(nav))
		}
		if nav[0].Href != "/" {
			t.Errorf("seed %d: first nav item href = %q, want /", i, nav[0].Href)
		}
		seen := map[string]bool{}
		for _, item := range nav {
			if seen[item.Href] {
				t.Errorf("seed %d: duplicate nav href %q", i, item.Href)
			}
			seen[item.Href] = true
			if item.Label == "" {
				t.Errorf("seed %d: empty nav label for %q", i, item.Href)
			}
		}
	}
}

// TestNavItems_SpaceCoversAliases 验证导航组合本身也在变化，
// 而不是每部署固定一套标签。
func TestNavItems_SpaceCoversAliases(t *testing.T) {
	combos := make(map[string]bool)
	for i := range 50 {
		withDeployment(t, seedOf(700+i), "")
		var labels []string
		for _, item := range depState.nav {
			labels = append(labels, item.Label+"@"+item.Href)
		}
		combos[strings.Join(labels, "|")] = true
	}
	if len(combos) < 30 {
		t.Errorf("only %d distinct nav combinations out of 50 seeds", len(combos))
	}
}

// ---------------------------------------------------------------------------
// HTTP 真实性层
// ---------------------------------------------------------------------------

func doFallback(seed []byte, target string, headers map[string]string, method string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	ServeFallback(rec, req)
	return rec
}

// TestServeFallback_ContentHeaders 验证真实 nginx 会发而 Go 默认不发的响应头。
func TestServeFallback_ContentHeaders(t *testing.T) {
	withDeployment(t, seedOf(800), "")

	rec := doFallback(seedOf(800), "/", nil, http.MethodGet)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	for _, header := range []string{"ETag", "Last-Modified", "Content-Length", "Accept-Ranges", "Server"} {
		if rec.Header().Get(header) == "" {
			t.Errorf("missing %s header", header)
		}
	}
	if got := rec.Header().Get("Content-Length"); got != fmt.Sprint(rec.Body.Len()) {
		t.Errorf("Content-Length = %s, body length = %d", got, rec.Body.Len())
	}
	if got := rec.Header().Get("Server"); got != "nginx" {
		t.Errorf("Server = %q, want nginx", got)
	}
	// Last-Modified 必须是可解析的 HTTP 日期。
	if _, err := http.ParseTime(rec.Header().Get("Last-Modified")); err != nil {
		t.Errorf("Last-Modified not parseable: %v", err)
	}
}

// TestServeFallback_UnknownPathStatus 验证浏览器式的内容请求对未知路径返回 404，
// 而非内容请求（客户端探测）保持 200 + 页面正文。
func TestServeFallback_UnknownPathStatus(t *testing.T) {
	withDeployment(t, seedOf(801), "")

	browser := map[string]string{"Accept": "text/html,application/xhtml+xml;q=0.9"}
	if rec := doFallback(seedOf(801), "/x9f2ab", browser, http.MethodGet); rec.Code != http.StatusNotFound {
		t.Errorf("unknown path with Accept: text/html: status = %d, want 404", rec.Code)
	}
	for _, path := range []string{"/", "/about", "/services", "/blog", "/contact"} {
		if rec := doFallback(seedOf(801), path, browser, http.MethodGet); rec.Code != http.StatusOK {
			t.Errorf("known path %q: status = %d, want 200", path, rec.Code)
		}
	}
	// 客户端探测不带 text/html：保持 200，避免改变既有客户端看到的响应形状。
	if rec := doFallback(seedOf(801), "/x9f2ab", nil, http.MethodGet); rec.Code != http.StatusOK {
		t.Errorf("unknown path without Accept: status = %d, want 200", rec.Code)
	}
}

// clientStreamHeaders 是 transport/http2 打开流时实际发送的请求头
// （见 transport/http2/client.go 的 Open）。
// 关键点是**没有 Accept 头**：服务端的 404 判定只看 Accept 是否含 text/html，
// 因此客户端的请求永远不会拿到 404。
func clientStreamHeaders(salt string) map[string]string {
	h := map[string]string{
		"User-Agent":    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
		"Content-Type":  "application/octet-stream",
		"Cache-Control": "no-store",
	}
	if salt != "" {
		h["x-es"] = salt
	}
	return h
}

func masterKeyForTest() []byte {
	key, err := crypto.DeriveMasterKey("test-password")
	if err != nil {
		panic(err)
	}
	return key
}

func serveProbe(t *testing.T, seed []byte, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	withDeployment(t, seed, "")
	h, err := NewProbeHandler(masterKeyForTest(), make([]byte, 64))
	if err != nil {
		panic(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/v3/probe", nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// TestClientRequestShapes_Always200 是本次改造的核心回归保护：客户端会遇到的
// 每一个 fallback 触发点都必须保持 200 + 页面正文。
//
// 判据不是"看起来对"，而是客户端自己的解析规则：
//   - 会话读取（client/proxy/stream.go:157）：非 200 → HandshakeRejectedError，
//     200 + HTML → 在记录解析层暴露异常。两条路都会失败，但只有 200 保留
//     原有的错误分类与日志/降级行为。
//   - 探测（transport/http2/probe.go:73-82）：非 200 → probeInconclusive
//     （当作临时拒绝、保持当前状态）；200 但非载荷 → probeUnsupported
//     （两次后永久转为被动检测）。若这里变成 404，客户端对"不提供 /v3/probe
//     的老服务端"的降级判定将永远无法完成。
func TestClientRequestShapes_Always200(t *testing.T) {
	// /v3/probe 上的两种非认证请求都由 ProbeHandler 触发 fallback。
	for _, tt := range []struct {
		name    string
		headers map[string]string
	}{
		{"probe no token", clientStreamHeaders("")},
		{"probe bad base64", clientStreamHeaders("not-base64!!")},
		{"probe wrong token", clientStreamHeaders("d3Jvbmd0b2tlbg")},
	} {
		t.Run(tt.name, func(t *testing.T) {
			rec := serveProbe(t, seedOf(810), tt.headers)
			if rec.Code != http.StatusOK {
				t.Errorf("status = %d, want 200 (client contract)", rec.Code)
			}
			if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
				t.Errorf("Content-Type = %q, want text/html", ct)
			}
			if rec.Body.Len() == 0 {
				t.Errorf("empty fallback body")
			}
		})
	}

	// 握手路径上的非 POST / 缺 x-es 请求同样落到 fallback。带有效 x-es 的
	// 解密失败路径由 reject_test.go 覆盖（同样断言 200）。
	h := NewProxyHandler(ProxyHandlerConfig{
		MasterKey: masterKeyForTest(),
		Timeouts:  sharedconfig.NewTimeouts(time.Second),
	})
	for _, tt := range []struct {
		name    string
		method  string
		body    []byte
		headers map[string]string
	}{
		{"get on tcp endpoint", http.MethodGet, []byte("x"), clientStreamHeaders("")},
		{"post without x-es", http.MethodPost, []byte("x"), clientStreamHeaders("")},
	} {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "/v3/tcp", bytes.NewReader(tt.body))
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}
			req.Header.Del("Accept")
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Errorf("status = %d, want 200 (client contract)", rec.Code)
			}
			if rec.Body.Len() == 0 {
				t.Error("empty fallback body")
			}
		})
	}
}

// TestEndpointRoutingContract 固化服务端 mux 的路由行为：/v3/* 四个端点都必须
// 命中各自 handler，绝不会掉进 "/" 的 fallback（否则客户端会因为路径不存在而
// 收到 404 之前的旧行为）。这四个 Handle 调用与 server/server.go 中注册的
// 模式必须保持一致。
func TestEndpointRoutingContract(t *testing.T) {
	const probeStub = "/v3/probe-stub"

	mux := http.NewServeMux()
	proxy := &ProxyHandler{} // 非 HTTP/2 请求会走 fallback，不解引用任何字段
	mux.Handle("/v3/tcp", proxy)
	mux.Handle("/v3/udp", proxy)
	mux.Handle("/v3/icmp", proxy)
	mux.Handle(probeStub, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !r.ProtoAtLeast(2, 0) {
			ServeFallback(w, r)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		ServeFallback(w, r)
	})

	withDeployment(t, seedOf(812), "")

	// 每个端点都必须命中自己的 handler，而不是 "/" 的 fallback。
	for _, endpoint := range []string{"/v3/tcp", "/v3/udp", "/v3/icmp", probeStub} {
		req := httptest.NewRequest(http.MethodPost, endpoint, nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Header().Get("Content-Type") == "" {
			t.Errorf("%s: no handler matched", endpoint)
		}
	}

	// 未知路径在客户端形状下仍是 200 + HTML（而非 404）。
	req := httptest.NewRequest(http.MethodGet, "/x9f2ab", nil)
	req.Header.Set("User-Agent", clientStreamHeaders("")["User-Agent"])
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("client-shaped unknown path: status = %d, want 200", rec.Code)
	}

	// 浏览器形状的未知路径得到 404。
	req = httptest.NewRequest(http.MethodGet, "/x9f2ab", nil)
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("browser-shaped unknown path: status = %d, want 404", rec.Code)
	}
}

// TestServeFallback_NotModified 覆盖条件请求矩阵。
func TestServeFallback_NotModified(t *testing.T) {
	withDeployment(t, seedOf(802), "")

	first := doFallback(seedOf(802), "/about", nil, http.MethodGet)
	etag := first.Header().Get("ETag")
	lastModified := first.Header().Get("Last-Modified")
	lm, err := http.ParseTime(lastModified)
	if err != nil {
		t.Fatalf("parse Last-Modified: %v", err)
	}

	tests := []struct {
		name    string
		headers map[string]string
		want    int
	}{
		{"no conditional headers", nil, http.StatusOK},
		{"matching etag", map[string]string{"If-None-Match": etag}, http.StatusNotModified},
		{"etag list", map[string]string{"If-None-Match": `"other", ` + etag}, http.StatusNotModified},
		{"weak etag", map[string]string{"If-None-Match": "W/" + etag}, http.StatusNotModified},
		{"wildcard etag", map[string]string{"If-None-Match": "*"}, http.StatusNotModified},
		{"stale etag", map[string]string{"If-None-Match": `"deadbeef"`}, http.StatusOK},
		{
			"same second ims",
			map[string]string{"If-Modified-Since": lm.Format(http.TimeFormat)},
			http.StatusNotModified,
		},
		{
			"later ims",
			map[string]string{"If-Modified-Since": lm.Add(time.Hour).Format(http.TimeFormat)},
			http.StatusNotModified,
		},
		{
			"earlier ims",
			map[string]string{"If-Modified-Since": lm.Add(-time.Hour).Format(http.TimeFormat)},
			http.StatusOK,
		},
		{
			"etag wins over stale ims",
			map[string]string{
				"If-None-Match":     etag,
				"If-Modified-Since": lm.Add(-time.Hour).Format(http.TimeFormat),
			},
			http.StatusNotModified,
		},
		{
			"etag wins over fresh ims",
			map[string]string{
				"If-None-Match":     `"deadbeef"`,
				"If-Modified-Since": lm.Add(time.Hour).Format(http.TimeFormat),
			},
			http.StatusOK,
		},
		{
			"malformed ims ignored",
			map[string]string{"If-Modified-Since": "not-a-date"},
			http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := doFallback(seedOf(802), "/about", tt.headers, http.MethodGet)
			if rec.Code != tt.want {
				t.Errorf("status = %d, want %d", rec.Code, tt.want)
			}
			if tt.want == http.StatusNotModified && rec.Body.Len() != 0 {
				t.Errorf("304 response carried %d body bytes", rec.Body.Len())
			}
			if tt.want == http.StatusNotModified {
				if got := rec.Header().Get("ETag"); got != etag {
					t.Errorf("304 ETag = %q, want %q", got, etag)
				}
			}
		})
	}
}

// TestServeFallback_Head 验证 HEAD 与 GET 报出相同的长度但无正文。
func TestServeFallback_Head(t *testing.T) {
	withDeployment(t, seedOf(803), "")

	get := doFallback(seedOf(803), "/services", nil, http.MethodGet)
	head := doFallback(seedOf(803), "/services", nil, http.MethodHead)

	if head.Header().Get("Content-Length") != get.Header().Get("Content-Length") {
		t.Errorf("HEAD Content-Length = %q, GET = %q",
			head.Header().Get("Content-Length"), get.Header().Get("Content-Length"))
	}
	// httptest.ResponseRecorder 不做 HEAD 去体（那是 net/http.Server 的职责），
	// 因此这里只断言长度契约。
	if head.Header().Get("Content-Length") == "" {
		t.Error("HEAD response lacks Content-Length")
	}
}

// TestServeFallback_ETagStablePerDeployment 验证同一路径的 ETag 在一个部署内
// 稳定，跨部署变化。真实静态文件的 ETag 也具备这两个性质。
func TestServeFallback_ETagStablePerDeployment(t *testing.T) {
	withDeployment(t, seedOf(804), "")
	first := doFallback(seedOf(804), "/about", nil, http.MethodGet).Header().Get("ETag")
	second := doFallback(seedOf(804), "/about", nil, http.MethodGet).Header().Get("ETag")
	if first != second {
		t.Errorf("ETag changed within a deployment: %q -> %q", first, second)
	}

	withDeployment(t, seedOf(805), "")
	other := doFallback(seedOf(805), "/about", nil, http.MethodGet).Header().Get("ETag")
	if other == first {
		t.Error("ETag identical across deployments")
	}
}

// TestServeFallback_CustomModesUnchanged 验证目录/自定义模式的行为与状态码
// 不受真实性层影响。
func TestServeFallback_CustomModesUnchanged(t *testing.T) {
	withDeployment(t, seedOf(806), "")

	dir := makeFallbackDir(t, map[string]string{
		"index.html": "<h1>Home</h1>",
		"404.html":   "<h1>Not Found</h1>",
	})
	if err := setFallbackDir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fallbackPages = nil; fallback404 = nil })

	browser := map[string]string{"Accept": "text/html"}
	rec := doFallback(seedOf(806), "/does-not-exist", browser, http.MethodGet)
	if rec.Code != http.StatusOK {
		t.Errorf("dir mode status = %d, want 200 (unchanged)", rec.Code)
	}
	if rec.Header().Get("ETag") != "" {
		t.Error("dir mode must not get generated-page caching headers")
	}
	if rec.Body.String() != "<h1>Not Found</h1>" {
		t.Errorf("dir mode body = %q", rec.Body.String())
	}
}

// TestThemesJSON_Structure 约束主题资源的结构，避免"改了资源、随机参数却失效"：
// token 必须落在模板里真实存在的元素上，且主题不能与模板脱节。
func TestThemesJSON_Structure(t *testing.T) {
	body := string(mustReadFallback("assets/fallback/template.html"))
	for _, want := range []string{
		`<p><span>{{.Tagline}}</span></p>`,
		"{{.HeadExtras}}",
		"{{.FooterNotice}}",
		"{{.BodyClass}}",
		"{{.Analytics}}",
		"{{.Description}}",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("template is missing %q", want)
		}
	}

	// 主题不能与模板脱节：头部的 tagline 必须包在可独立设置透明度的 <span> 里。
	for _, theme := range themes {
		if !strings.Contains(string(theme.CSS), "header p span{opacity:{{tagline_opacity}}}") {
			t.Errorf("theme %q: tagline opacity is not scoped to the template's <span>", theme.Name)
		}
		if !strings.Contains(string(theme.CSS), "main a{color:{{accent_text}}}") {
			t.Errorf("theme %q: accent_text token is not applied to a real element", theme.Name)
		}
	}
}

// ---------------------------------------------------------------------------
// 渲染辅助
// ---------------------------------------------------------------------------

// renderAll 用给定种子渲染一组路径，返回 路径→字节。
func renderAll(t *testing.T, seed []byte) map[string][]byte {
	t.Helper()
	withDeployment(t, seed, "")
	out := make(map[string][]byte)
	for _, path := range []string{"/", "/about", "/services", "/blog", "/contact", "/random"} {
		out[path] = renderPage(path)
	}
	return out
}

// byteDiffRatio 返回两个字节串中不同位置的相对数量。
func byteDiffRatio(a, b []byte) float64 {
	if len(a) == 0 && len(b) == 0 {
		return 0
	}
	diff := 0
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			diff++
		}
	}
	diff += abs(len(a) - len(b))
	return float64(diff) / float64(max(len(a), len(b)))
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}
