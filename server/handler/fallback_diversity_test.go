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

// depState 是 withDeployment 最近构造出的实例的部署身份，仅用于断言。
var depState *deployment

// withDeployment 用固定种子/主题构造独立实例并设为包级内置实例
// （serveProbe 与零值 ProxyHandler 也拿到同一套身份），测试结束清空。
func withDeployment(t *testing.T, seed []byte, theme string) *Fallback {
	t.Helper()
	fb, err := NewFallback(FallbackConfig{}, WithSeed(seed), WithTheme(theme))
	if err != nil {
		t.Fatalf("NewFallback: %v", err)
	}
	setBuiltinFallbackForTest(fb)
	depState = fb.dep
	t.Cleanup(func() {
		setBuiltinFallbackForTest(nil)
		depState = nil
	})
	return fb
}

func seedOf(n int) []byte {
	s := seed32(n)
	return s[:]
}

func seed32(n int) [32]byte {
	return sha256.Sum256([]byte(fmt.Sprintf("test-seed-%d", n)))
}

func TestInitFallback_Deterministic(t *testing.T) {
	first := renderAll(t, seedOf(1))
	second := renderAll(t, seedOf(1))

	for path, body := range first {
		if !bytes.Equal(second[path], body) {
			t.Errorf("path %q: same seed produced different bytes", path)
		}
	}
}

func TestFallbackInstance_Isolated(t *testing.T) {
	first := withDeployment(t, seedOf(2), "")
	firstHome := first.renderPage("/")

	second := withDeployment(t, seedOf(3), "")
	secondHome := second.renderPage("/")

	if bytes.Equal(firstHome, secondHome) {
		t.Error("two instances produced the same home page")
	}
	if first.dep.site.Name == second.dep.site.Name {
		t.Errorf("two instances produced the same site name %q", first.dep.site.Name)
	}
	if !bytes.Equal(firstHome, first.renderPage("/")) {
		t.Error("an instance changed its own rendering after another instance was constructed")
	}
}

// 包级内置实例的惰性构造在并发下安全，且所有调用者拿到同一个实例。
func TestBuiltinFallback_ConcurrentInit(t *testing.T) {
	fb, err := NewFallback(FallbackConfig{}, WithSeed(seedOf(4)))
	if err != nil {
		t.Fatalf("NewFallback: %v", err)
	}
	setBuiltinFallbackForTest(fb)
	t.Cleanup(func() { setBuiltinFallbackForTest(nil) })

	var wg sync.WaitGroup
	results := make([]*Fallback, 50)
	for i := range 50 {
		wg.Go(func() { results[i] = builtinFallback() })
	}
	wg.Wait()

	if results[0] == nil {
		t.Fatal("deployment not initialized")
	}
	for i, got := range results {
		if got != results[0] {
			t.Fatalf("call %d got a different builtin instance", i)
		}
	}
	if results[0].dep == nil {
		t.Fatal("builtin instance has no deployment identity")
	}
}

// 不同部署的首页字节差异率要足够高，站点名与 Last-Modified 也要不同。
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

func TestInitFallback_DeploymentSpace(t *testing.T) {
	palettes := make(map[string]int)
	homes := make(map[string]int)
	for i := range 50 {
		fb := withDeployment(t, seedOf(100+i), "")
		palettes[strongETag([]byte(fb.dep.theme.CSS))]++
		homes[strongETag(fb.renderPage("/"))]++
	}

	if distinct := len(palettes); distinct < 45 {
		t.Errorf("only %d distinct palettes out of 50 seeds", distinct)
	}
	if distinct := len(homes); distinct < 50 {
		t.Errorf("only %d distinct home pages out of 50 seeds", distinct)
	}
}

// 首页可见组合空间（跨部署）必须远大于固定主题与文案的乘积。
// 用各池实际规模相乘得到下界：任何一个池被改小，这条断言就会失败。
func TestVisibleCombinationSpace(t *testing.T) {
	withDeployment(t, seedOf(900), "")

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
	if siteNames < 100 {
		t.Errorf("site name space = %d, want >= 100", siteNames)
	}
}

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

func TestNewSiteIdentity_PoolCoverage(t *testing.T) {
	names := make(map[string]bool)
	for i := range 200 {
		names[newSiteIdentity(seed32(200+i)).Name] = true
	}
	if len(names) < 100 {
		t.Errorf("only %d distinct site names out of 200 seeds", len(names))
	}
}

var placeholderRe = regexp.MustCompile(`\{\{\w+\}\}`)

// 任何一次派生都不得把 {{token}} 占位符发给扫描器。
func TestThemeCSSTokensResolved(t *testing.T) {
	for i := range 20 {
		fb := withDeployment(t, seedOf(300+i), "")

		css := string(fb.dep.theme.CSS)
		if m := placeholderRe.FindString(css); m != "" {
			t.Fatalf("seed %d: unreplaced token %s in theme CSS", i, m)
		}
		if strings.Contains(css, "{{") || strings.Contains(css, "}}") {
			t.Fatalf("seed %d: leftover braces in theme CSS", i)
		}
		if strings.Contains(css, "#") && strings.Contains(css, "{{") {
			t.Fatalf("seed %d: mixed tokens and literals", i)
		}
	}
}

// 任意一次派生都要得到可读配色：主题 CSS 里的 token 已被替换，只能直接校验调色板。
func TestThemeCSS_Contrast(t *testing.T) {
	for i := range 40 {
		fb := withDeployment(t, seedOf(400+i), "")
		for _, check := range validatePalette(themePalette(fb.dep.seed, fb.dep.theme)) {
			if check.Got < check.Min-0.01 {
				t.Errorf("seed %d: %s contrast = %.2f, want >= %.2f",
					i, check.Name, check.Got, check.Min)
			}
		}
	}
}

// 拼错的 token 会原样出现在发给扫描器的 CSS 里。
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

func TestComposeContent_Shape(t *testing.T) {
	fb := withDeployment(t, seedOf(500), "")

	for _, path := range []string{"/", "/about", "/services", "/blog", "/contact", "/random"} {
		content := composeContent(fb.dep, path, detectPageType(path))
		if n := len(content.Paragraphs); n < 2 || n > 6 {
			t.Errorf("path %q: %d paragraphs, want 2-6", path, n)
		}
		if strings.TrimSpace(content.Heading) == "" {
			t.Errorf("path %q: empty heading", path)
		}
		if strings.TrimSpace(content.Footer) == "" {
			t.Errorf("path %q: empty footer", path)
		}
		// 页脚的 {site}/{year} 未解析就会把字面占位符发给扫描器。
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

// 资源文件缺字段时不能 panic：rand.IntN(0) 会 panic，空池必须有守卫。
func TestComposeContent_EmptyPools(t *testing.T) {
	fb := withDeployment(t, seedOf(501), "")

	saved := contentPools
	contentPools = contentPool{}
	t.Cleanup(func() { contentPools = saved })

	content := composeContent(fb.dep, "/", "home")
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

func TestLegacyContentPool(t *testing.T) {
	fb := withDeployment(t, seedOf(502), "")

	saved := contentPools
	contentPools = contentPool{Pages: legacyPool{
		"home": {{Title: "Legacy Home", Heading: "Legacy Heading", Paragraphs: []string{"Legacy paragraph."}}},
	}}
	t.Cleanup(func() { contentPools = saved })

	content := composeContent(fb.dep, "/", "home")
	if content.Heading != "Legacy Heading" {
		t.Errorf("legacy heading = %q", content.Heading)
	}
	if len(content.Paragraphs) != 1 || content.Paragraphs[0] != "Legacy paragraph." {
		t.Errorf("legacy paragraphs = %v", content.Paragraphs)
	}
}

func TestNavItems_LinksResolve(t *testing.T) {
	for i := range 50 {
		fb := withDeployment(t, seedOf(600+i), "")
		nav := fb.dep.nav

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

func TestNavItems_SpaceCoversAliases(t *testing.T) {
	combos := make(map[string]bool)
	for i := range 50 {
		fb := withDeployment(t, seedOf(700+i), "")
		var labels []string
		for _, item := range fb.dep.nav {
			labels = append(labels, item.Label+"@"+item.Href)
		}
		combos[strings.Join(labels, "|")] = true
	}
	if len(combos) < 30 {
		t.Errorf("only %d distinct nav combinations out of 50 seeds", len(combos))
	}
}

func doFallback(fb *Fallback, target string, headers map[string]string, method string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	fb.Serve(rec, req)
	return rec
}

func TestServeFallback_ContentHeaders(t *testing.T) {
	fb := withDeployment(t, seedOf(800), "")

	rec := doFallback(fb, "/", nil, http.MethodGet)
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
	if _, err := http.ParseTime(rec.Header().Get("Last-Modified")); err != nil {
		t.Errorf("Last-Modified not parseable: %v", err)
	}
}

// 浏览器式请求（Accept 含 text/html）对未知路径返回 404，客户端探测仍保持 200。
func TestServeFallback_UnknownPathStatus(t *testing.T) {
	fb := withDeployment(t, seedOf(801), "")

	browser := map[string]string{"Accept": "text/html,application/xhtml+xml;q=0.9"}
	if rec := doFallback(fb, "/x9f2ab", browser, http.MethodGet); rec.Code != http.StatusNotFound {
		t.Errorf("unknown path with Accept: text/html: status = %d, want 404", rec.Code)
	}
	for _, path := range []string{"/", "/about", "/services", "/blog", "/contact"} {
		if rec := doFallback(fb, path, browser, http.MethodGet); rec.Code != http.StatusOK {
			t.Errorf("known path %q: status = %d, want 200", path, rec.Code)
		}
	}
	// 客户端探测不带 text/html，保持 200 以维持既有响应形状。
	if rec := doFallback(fb, "/x9f2ab", nil, http.MethodGet); rec.Code != http.StatusOK {
		t.Errorf("unknown path without Accept: status = %d, want 200", rec.Code)
	}
}

// 客户端打开的流不带 Accept 头，服务端的 404 判定只看 Accept 是否含 text/html，
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
	fb := withDeployment(t, seed, "")
	h, err := NewProbeHandler(masterKeyForTest(), make([]byte, 64), fb)
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

// 客户端会遇到的每个 fallback 触发点都必须保持 200 + 页面正文：
// 非 200 会让会话读取报 HandshakeRejectedError、让探测判成 probeInconclusive
// （对不提供 /v3/probe 的老服务端的降级判定永远无法完成）。
func TestClientRequestShapes_Always200(t *testing.T) {
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

	// 带有效 x-es 的解密失败路径由 reject_test.go 覆盖（同样断言 200）。
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

// /v3/* 四个端点都必须命中各自 handler，绝不掉进 "/" 的 fallback；
// 这四个 Handle 调用与 server/server.go 的注册模式必须一致。
func TestEndpointRoutingContract(t *testing.T) {
	const probeStub = "/v3/probe-stub"

	fb := withDeployment(t, seedOf(812), "")

	mux := http.NewServeMux()
	proxy := &ProxyHandler{} // 非 HTTP/2 请求会走内置 fallback，不解引用任何字段
	mux.Handle("/v3/tcp", proxy)
	mux.Handle("/v3/udp", proxy)
	mux.Handle("/v3/icmp", proxy)
	mux.Handle(probeStub, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !r.ProtoAtLeast(2, 0) {
			fb.Serve(w, r)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fb.Serve(w, r)
	})

	for _, endpoint := range []string{"/v3/tcp", "/v3/udp", "/v3/icmp", probeStub} {
		req := httptest.NewRequest(http.MethodPost, endpoint, nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Header().Get("Content-Type") == "" {
			t.Errorf("%s: no handler matched", endpoint)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/x9f2ab", nil)
	req.Header.Set("User-Agent", clientStreamHeaders("")["User-Agent"])
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("client-shaped unknown path: status = %d, want 200", rec.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/x9f2ab", nil)
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("browser-shaped unknown path: status = %d, want 404", rec.Code)
	}
}

func TestServeFallback_NotModified(t *testing.T) {
	fb := withDeployment(t, seedOf(802), "")

	first := doFallback(fb, "/about", nil, http.MethodGet)
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
			rec := doFallback(fb, "/about", tt.headers, http.MethodGet)
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

func TestServeFallback_Head(t *testing.T) {
	fb := withDeployment(t, seedOf(803), "")

	get := doFallback(fb, "/services", nil, http.MethodGet)
	head := doFallback(fb, "/services", nil, http.MethodHead)

	if head.Header().Get("Content-Length") != get.Header().Get("Content-Length") {
		t.Errorf("HEAD Content-Length = %q, GET = %q",
			head.Header().Get("Content-Length"), get.Header().Get("Content-Length"))
	}
	// ResponseRecorder 不做 HEAD 去体（那是 net/http.Server 的职责），只断言长度契约。
	if head.Header().Get("Content-Length") == "" {
		t.Error("HEAD response lacks Content-Length")
	}
}

func TestServeFallback_ETagStablePerDeployment(t *testing.T) {
	fb := withDeployment(t, seedOf(804), "")
	first := doFallback(fb, "/about", nil, http.MethodGet).Header().Get("ETag")
	second := doFallback(fb, "/about", nil, http.MethodGet).Header().Get("ETag")
	if first != second {
		t.Errorf("ETag changed within a deployment: %q -> %q", first, second)
	}

	other := withDeployment(t, seedOf(805), "")
	otherETag := doFallback(other, "/about", nil, http.MethodGet).Header().Get("ETag")
	if otherETag == first {
		t.Error("ETag identical across deployments")
	}
}

func TestServeFallback_CustomModesUnchanged(t *testing.T) {
	fb := withDeployment(t, seedOf(806), "")

	dir := makeFallbackDir(t, map[string]string{
		"index.html": "<h1>Home</h1>",
		"404.html":   "<h1>Not Found</h1>",
	})
	if err := fb.setDir(dir); err != nil {
		t.Fatal(err)
	}

	browser := map[string]string{"Accept": "text/html"}
	rec := doFallback(fb, "/does-not-exist", browser, http.MethodGet)
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

// token 必须落在模板里真实存在的元素上，主题不能与模板脱节。
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

	for _, theme := range themes {
		if !strings.Contains(string(theme.CSS), "header p span{opacity:{{tagline_opacity}}}") {
			t.Errorf("theme %q: tagline opacity is not scoped to the template's <span>", theme.Name)
		}
		if !strings.Contains(string(theme.CSS), "main a{color:{{accent_text}}}") {
			t.Errorf("theme %q: accent_text token is not applied to a real element", theme.Name)
		}
	}
}

func renderAll(t *testing.T, seed []byte) map[string][]byte {
	t.Helper()
	fb := withDeployment(t, seed, "")
	out := make(map[string][]byte)
	for _, path := range []string{"/", "/about", "/services", "/blog", "/contact", "/random"} {
		out[path] = fb.renderPage(path)
	}
	return out
}

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
