package handler

import (
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestServeFallback_DifferentPathsDifferentContent(t *testing.T) {
	fb := newTestFallback(t)
	paths := []string{"/", "/about", "/contact", "/services", "/blog"}
	seen := make(map[string]string)

	for _, path := range paths {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		fb.Serve(rec, req)

		body := rec.Body.String()
		if body == "" {
			t.Errorf("empty body for path %q", path)
		}
		if prev, ok := seen[body]; ok {
			t.Errorf("path %q returned same content as %q", path, prev)
		}
		seen[body] = path
	}
}

func TestServeFallback_SamePathSameContent(t *testing.T) {
	fb := newTestFallback(t)
	req1 := httptest.NewRequest(http.MethodGet, "/about", nil)
	rec1 := httptest.NewRecorder()
	fb.Serve(rec1, req1)

	req2 := httptest.NewRequest(http.MethodGet, "/about", nil)
	rec2 := httptest.NewRecorder()
	fb.Serve(rec2, req2)

	if rec1.Body.String() != rec2.Body.String() {
		t.Error("same path returned different content")
	}
}

func TestServeFallback_CustomHTML(t *testing.T) {
	fb := newTestFallback(t)
	custom := []byte("<html><body>custom</body></html>")
	fb.setHTML(custom)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	fb.Serve(rec, req)

	if rec.Body.String() != string(custom) {
		t.Errorf("expected custom HTML, got %q", rec.Body.String())
	}
}

func TestResolveTitle(t *testing.T) {
	if resolveTitle("Hello", "Site") != "Hello" {
		t.Error("expected Hello")
	}
	if resolveTitle(" ", "Site") != "Site" {
		t.Error("expected Site for whitespace")
	}
	if resolveTitle("", "Site") != "Site" {
		t.Error("expected Site for empty")
	}
}

func TestDetectPageType(t *testing.T) {
	tests := []struct{ path, want string }{
		{"/", "home"},
		{"/about", "about"},
		{"/about/team", "about"},
		{"/contact", "contact"},
		{"/support", "contact"},
		{"/help", "contact"},
		{"/services", "services"},
		{"/services/consulting", "services"},
		{"/blog", "blog"},
		{"/blog/article", "blog"},
		{"/news", "blog"},
		{"/articles", "blog"},
		{"/random-path", "generic"},
		{"/api/v1", "generic"},
	}

	for _, tt := range tests {
		got := detectPageType(tt.path)
		if got != tt.want {
			t.Errorf("detectPageType(%q) = %q, want %q", tt.path, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// 基于目录的回退页面测试
// ---------------------------------------------------------------------------

func makeFallbackDir(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		full := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(full), 0700); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(full, []byte(content), 0600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	return dir
}

func TestSetFallbackDir_ExactPathMatch(t *testing.T) {
	fb := newTestFallback(t)
	dir := makeFallbackDir(t, map[string]string{
		"index.html":   "<h1>Home</h1>",
		"about.html":   "<h1>About</h1>",
		"contact.html": "<h1>Contact</h1>",
	})
	if err := fb.setDir(dir); err != nil {
		t.Fatal(err)
	}

	for _, tt := range []struct{ path, want string }{
		{"/", "<h1>Home</h1>"},
		{"/about", "<h1>About</h1>"},
		{"/contact", "<h1>Contact</h1>"},
		{"/about/", "<h1>About</h1>"},
	} {
		req := httptest.NewRequest(http.MethodGet, tt.path, nil)
		rec := httptest.NewRecorder()
		fb.Serve(rec, req)
		if rec.Body.String() != tt.want {
			t.Errorf("path %q: got %q, want %q", tt.path, rec.Body.String(), tt.want)
		}
	}
}

func TestSetFallbackDir_IndexMapping(t *testing.T) {
	fb := newTestFallback(t)
	dir := makeFallbackDir(t, map[string]string{
		"index.html": "<h1>Root</h1>",
	})
	if err := fb.setDir(dir); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	fb.Serve(rec, req)
	if rec.Body.String() != "<h1>Root</h1>" {
		t.Errorf("got %q, want %q", rec.Body.String(), "<h1>Root</h1>")
	}
}

func TestSetFallbackDir_404Fallback(t *testing.T) {
	fb := newTestFallback(t)
	dir := makeFallbackDir(t, map[string]string{
		"index.html": "<h1>Home</h1>",
		"404.html":   "<h1>Not Found</h1>",
	})
	if err := fb.setDir(dir); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/nonexistent", nil)
	rec := httptest.NewRecorder()
	fb.Serve(rec, req)
	if rec.Body.String() != "<h1>Not Found</h1>" {
		t.Errorf("got %q, want %q", rec.Body.String(), "<h1>Not Found</h1>")
	}
}

func TestSetFallbackDir_No404FallbackToIndex(t *testing.T) {
	fb := newTestFallback(t)
	dir := makeFallbackDir(t, map[string]string{
		"index.html": "<h1>Home</h1>",
	})
	if err := fb.setDir(dir); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/nonexistent", nil)
	rec := httptest.NewRecorder()
	fb.Serve(rec, req)
	if rec.Body.String() != "<h1>Home</h1>" {
		t.Errorf("got %q, want %q", rec.Body.String(), "<h1>Home</h1>")
	}
}

func TestSetFallbackDir_NestedSubdirs(t *testing.T) {
	fb := newTestFallback(t)
	dir := makeFallbackDir(t, map[string]string{
		"index.html":      "<h1>Home</h1>",
		"blog/post1.html": "<h1>Post 1</h1>",
		"blog/post2.html": "<h1>Post 2</h1>",
	})
	if err := fb.setDir(dir); err != nil {
		t.Fatal(err)
	}

	for _, tt := range []struct{ path, want string }{
		{"/", "<h1>Home</h1>"},
		{"/blog/post1", "<h1>Post 1</h1>"},
		{"/blog/post2", "<h1>Post 2</h1>"},
	} {
		req := httptest.NewRequest(http.MethodGet, tt.path, nil)
		rec := httptest.NewRecorder()
		fb.Serve(rec, req)
		if rec.Body.String() != tt.want {
			t.Errorf("path %q: got %q, want %q", tt.path, rec.Body.String(), tt.want)
		}
	}
}

func TestSetFallbackDir_ImplicitIndex(t *testing.T) {
	fb := newTestFallback(t)
	dir := makeFallbackDir(t, map[string]string{
		"index.html":      "<h1>Home</h1>",
		"blog/index.html": "<h1>Blog Home</h1>",
		"blog/post1.html": "<h1>Post 1</h1>",
	})
	if err := fb.setDir(dir); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/blog", nil)
	rec := httptest.NewRecorder()
	fb.Serve(rec, req)
	if rec.Body.String() != "<h1>Blog Home</h1>" {
		t.Errorf("got %q, want %q", rec.Body.String(), "<h1>Blog Home</h1>")
	}

	// /blog/ 路径也应生效
	req2 := httptest.NewRequest(http.MethodGet, "/blog/", nil)
	rec2 := httptest.NewRecorder()
	fb.Serve(rec2, req2)
	if rec2.Body.String() != "<h1>Blog Home</h1>" {
		t.Errorf("got %q, want %q", rec2.Body.String(), "<h1>Blog Home</h1>")
	}
}

func TestSetFallbackDir_IgnoresNonHTML(t *testing.T) {
	fb := newTestFallback(t)
	dir := makeFallbackDir(t, map[string]string{
		"index.html": "<h1>Home</h1>",
		"style.css":  "body { color: red; }",
		"readme.txt": "hello",
	})
	if err := fb.setDir(dir); err != nil {
		t.Fatal(err)
	}

	// /style 不应匹配到 style.css（它不是 .html 文件）
	req := httptest.NewRequest(http.MethodGet, "/style", nil)
	rec := httptest.NewRecorder()
	fb.Serve(rec, req)
	// 应回退到 index 页面
	if rec.Body.String() != "<h1>Home</h1>" {
		t.Errorf("got %q, want index fallback %q", rec.Body.String(), "<h1>Home</h1>")
	}
}

func TestSetFallbackDir_EmptyDir(t *testing.T) {
	fb := newTestFallback(t)
	dir := makeFallbackDir(t, map[string]string{})
	if err := fb.setDir(dir); err != nil {
		t.Fatal(err)
	}

	// 空目录时回退到自动生成页面（或已设置的自定义 fallback）。
	// 这里验证返回的 body 非空。
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	fb.Serve(rec, req)
	if rec.Body.Len() == 0 {
		t.Error("expected non-empty body from auto-generated fallback")
	}
}

func TestServeFallback_DirPriorityOverCustomHTML(t *testing.T) {
	fb := newTestFallback(t)
	dir := makeFallbackDir(t, map[string]string{
		"index.html": "<h1>Dir Home</h1>",
	})
	if err := fb.setDir(dir); err != nil {
		t.Fatal(err)
	}
	fb.setHTML([]byte("<h1>Custom</h1>"))

	// 目录模式优先于单文件自定义 HTML。
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	fb.Serve(rec, req)
	if rec.Body.String() != "<h1>Dir Home</h1>" {
		t.Errorf("got %q, want dir mode %q", rec.Body.String(), "<h1>Dir Home</h1>")
	}
}

// ---------------------------------------------------------------------------
// 反向代理回退测试
// ---------------------------------------------------------------------------

func TestSetFallbackProxy_EmptyURL(t *testing.T) {
	fb := newTestFallback(t)
	// 设置空 URL 应禁用代理（不报错）。
	if err := fb.setProxy("", false, nil); err != nil {
		t.Fatalf("unexpected error for empty URL: %v", err)
	}
	if fb.proxy != nil {
		t.Error("expected fb.proxy to be nil after empty URL")
	}
}

func TestSetFallbackProxy_InvalidURL(t *testing.T) {
	fb := newTestFallback(t)
	if err := fb.setProxy("://invalid", false, nil); err == nil {
		t.Error("expected error for invalid URL")
	}
}

func TestServeFallback_ProxyForwardsRequest(t *testing.T) {
	fb := newTestFallback(t)
	// 启动一个返回已知响应的测试用上游服务器。
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Upstream", "true")
		w.Write([]byte("from-upstream:" + r.URL.Path)) //nolint:errcheck
	}))
	defer upstream.Close()

	if err := fb.setProxy(upstream.URL, false, nil); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/some/path", nil)
	rec := httptest.NewRecorder()
	fb.Serve(rec, req)

	if rec.Body.String() != "from-upstream:/some/path" {
		t.Errorf("got %q, want %q", rec.Body.String(), "from-upstream:/some/path")
	}
	if rec.Header().Get("X-Upstream") != "true" {
		t.Error("expected X-Upstream header from upstream server")
	}
}

func TestServeFallback_ProxyHighestPriority(t *testing.T) {
	fb := newTestFallback(t)
	// 启动一个测试用上游服务器。
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("proxy-response")) //nolint:errcheck
	}))
	defer upstream.Close()

	if err := fb.setProxy(upstream.URL, false, nil); err != nil {
		t.Fatal(err)
	}

	// 同时设置目录和自定义 HTML 回退，以验证代理的优先级更高。
	dir := makeFallbackDir(t, map[string]string{
		"index.html": "<h1>Dir Home</h1>",
	})
	if err := fb.setDir(dir); err != nil {
		t.Fatal(err)
	}
	fb.setHTML([]byte("<h1>Custom</h1>"))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	fb.Serve(rec, req)

	// 代理应同时优先于目录和自定义 HTML。
	if rec.Body.String() != "proxy-response" {
		t.Errorf("got %q, want %q", rec.Body.String(), "proxy-response")
	}
}

// ---------------------------------------------------------------------------
// SetFallbackTarget 自动识别测试
// ---------------------------------------------------------------------------

func TestSetFallbackTarget_Empty(t *testing.T) {
	fb := newTestFallback(t)
	// 先配置一个反代目标，再用空字符串重置回内置生成页模式。
	if err := fb.SetTarget("http://127.0.0.1:8080", true, []string{"cdn.example.com"}); err != nil {
		t.Fatal(err)
	}

	if err := fb.SetTarget("", false, nil); err != nil {
		t.Fatal(err)
	}

	if fb.proxy != nil {
		t.Error("fb.proxy should be nil after reset")
	}
	if fb.cdnHosts != nil {
		t.Error("fb.cdnHosts should be nil after reset")
	}
	if fb.pages != nil {
		t.Error("fb.pages should be nil after reset")
	}
	if fb.page404 != nil {
		t.Error("fb.page404 should be nil after reset")
	}
	if fb.custom != nil {
		t.Error("fb.custom should be nil after reset")
	}

	// 重置后必须回到内置生成页：带 HTTP 真实性层的 200 + 页面正文。
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	fb.Serve(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if rec.Header().Get("ETag") == "" {
		t.Error("reset target should serve the generated page with its HTTP realism headers")
	}
}

func TestSetFallbackTarget_HTTPURL(t *testing.T) {
	fb := newTestFallback(t)

	if err := fb.SetTarget("http://127.0.0.1:8080", false, nil); err != nil {
		t.Fatal(err)
	}
	if fb.proxy == nil {
		t.Error("expected fb.proxy to be set for HTTP URL")
	}
}

func TestSetFallbackTarget_HTTPSURL(t *testing.T) {
	fb := newTestFallback(t)

	if err := fb.SetTarget("https://example.com", false, nil); err != nil {
		t.Fatal(err)
	}
	if fb.proxy == nil {
		t.Error("expected fb.proxy to be set for HTTPS URL")
	}
}

func TestSetFallbackTarget_Directory(t *testing.T) {
	fb := newTestFallback(t)
	dir := makeFallbackDir(t, map[string]string{
		"index.html": "<h1>Home</h1>",
	})

	if err := fb.SetTarget(dir, false, nil); err != nil {
		t.Fatal(err)
	}
	if len(fb.pages) == 0 {
		t.Error("expected fb.pages to be populated for directory")
	}
}

func TestSetFallbackTarget_File(t *testing.T) {
	fb := newTestFallback(t)
	dir := makeFallbackDir(t, map[string]string{
		"custom.html": "<h1>Custom</h1>",
	})
	filePath := filepath.Join(dir, "custom.html")

	if err := fb.SetTarget(filePath, false, nil); err != nil {
		t.Fatal(err)
	}
	if string(fb.custom) != "<h1>Custom</h1>" {
		t.Errorf("got %q, want %q", string(fb.custom), "<h1>Custom</h1>")
	}
}

func TestSetFallbackTarget_InvalidPath(t *testing.T) {
	fb := newTestFallback(t)
	if err := fb.SetTarget("/nonexistent/path", false, nil); err == nil {
		t.Error("expected error for nonexistent path")
	}
}

func TestSetFallbackTarget_ProxyEndToEnd(t *testing.T) {
	fb := newTestFallback(t)
	// 完整集成：用 HTTP URL 调用 SetFallbackTarget 后再服务一个请求。
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("upstream:" + r.URL.Path)) //nolint:errcheck
	}))
	defer upstream.Close()

	if err := fb.SetTarget(upstream.URL, false, nil); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/hello", nil)
	rec := httptest.NewRecorder()
	fb.Serve(rec, req)

	if rec.Body.String() != "upstream:/hello" {
		t.Errorf("got %q, want %q", rec.Body.String(), "upstream:/hello")
	}
}

// ---------------------------------------------------------------------------
// setFallbackProxy 的 Host 头与 Location 重写测试
// ---------------------------------------------------------------------------

// TestSetFallbackProxy_HostHeader 验证转发给上游的请求带的是上游的 Host
// （而非面向客户端的 host）。
// 这是核心修复：没有它，像 GitHub 这样的上游会返回
// 指向其规范域名的 301 重定向，导致浏览器地址栏跳转。
func TestSetFallbackProxy_HostHeader(t *testing.T) {
	fb := newTestFallback(t)
	var gotHost string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Host
		w.Write([]byte("ok")) //nolint:errcheck
	}))
	defer upstream.Close()

	if err := fb.setProxy(upstream.URL, false, nil); err != nil {
		t.Fatal(err)
	}

	// 面向客户端的请求使用不同的 host。
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "my-site.com"
	rec := httptest.NewRecorder()
	fb.Serve(rec, req)

	want := upstream.Listener.Addr().String()
	if gotHost != want {
		t.Errorf("upstream received Host %q, want %q", gotHost, want)
	}
}

// TestSetFallbackProxy_RewriteLocation 验证指向上游 host 的 3xx Location 头
// 会被重写回面向客户端的 host。
func TestSetFallbackProxy_RewriteLocation(t *testing.T) {
	fb := newTestFallback(t)
	var upstreamHost string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 模拟一个重定向到自身规范 URL 的上游。
		w.Header().Set("Location", "http://"+upstreamHost+"/some/path")
		w.WriteHeader(http.StatusMovedPermanently)
	}))
	defer upstream.Close()
	upstreamHost = upstream.Listener.Addr().String()

	if err := fb.setProxy(upstream.URL, false, nil); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "my-site.com"
	rec := httptest.NewRecorder()
	fb.Serve(rec, req)

	// httptest.NewRequest 的 TLS 为 nil，因此面向客户端的 scheme 是 "http"。
	if got := rec.Header().Get("Location"); got != "http://my-site.com/some/path" {
		t.Errorf("Location = %q, want %q", got, "http://my-site.com/some/path")
	}
}

// TestSetFallbackProxy_RelativeLocationUnchanged 验证相对路径的 Location 头
// （例如 "/login"）会原样透传。
func TestSetFallbackProxy_RelativeLocationUnchanged(t *testing.T) {
	fb := newTestFallback(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "/login")
		w.WriteHeader(http.StatusFound)
	}))
	defer upstream.Close()

	if err := fb.setProxy(upstream.URL, false, nil); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "my-site.com"
	rec := httptest.NewRecorder()
	fb.Serve(rec, req)

	if got := rec.Header().Get("Location"); got != "/login" {
		t.Errorf("Location = %q, want %q", got, "/login")
	}
}

// TestSetFallbackProxy_OtherHostLocationUnchanged 验证指向非上游 host 的
// Location 头会原样透传。
func TestSetFallbackProxy_OtherHostLocationUnchanged(t *testing.T) {
	fb := newTestFallback(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "https://other.example.com/x")
		w.WriteHeader(http.StatusFound)
	}))
	defer upstream.Close()

	if err := fb.setProxy(upstream.URL, false, nil); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "my-site.com"
	rec := httptest.NewRecorder()
	fb.Serve(rec, req)

	if got := rec.Header().Get("Location"); got != "https://other.example.com/x" {
		t.Errorf("Location = %q, want %q", got, "https://other.example.com/x")
	}
}

// TestSetFallbackProxy_PreserveHost 验证当 preserveHost 为 true 时，
// 面向客户端的 Host 头会原样转发给上游。
// 本地 nginx 基于 server_name 做虚拟主机路由的配置
// 需要这一行为。
func TestSetFallbackProxy_PreserveHost(t *testing.T) {
	fb := newTestFallback(t)
	var gotHost string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Host
		w.Write([]byte("ok")) //nolint:errcheck
	}))
	defer upstream.Close()

	if err := fb.setProxy(upstream.URL, true, nil); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "my-site.com"
	rec := httptest.NewRecorder()
	fb.Serve(rec, req)

	if gotHost != "my-site.com" {
		t.Errorf("upstream received Host %q, want %q (preserveHost=true)", gotHost, "my-site.com")
	}
}

// TestSetFallbackProxy_PreserveHostLocationRewrite 验证当 preserveHost
// 为 true 时 Location 重写仍然生效：如果上游（收到的是面向客户端的
// Host）重定向到其自身地址（例如 nginx 配置中通过 $host 生成），
// 则 Location 会被重写回
// 面向客户端的 host。
func TestSetFallbackProxy_PreserveHostLocationRewrite(t *testing.T) {
	fb := newTestFallback(t)
	var upstreamHost string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 上游重定向到自身的监听地址（例如 nginx 配置中
		// 使用 $host 但没有匹配的 server_name）。
		w.Header().Set("Location", "http://"+upstreamHost+"/login")
		w.WriteHeader(http.StatusFound)
	}))
	defer upstream.Close()
	upstreamHost = upstream.Listener.Addr().String()

	if err := fb.setProxy(upstream.URL, true, nil); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "my-site.com"
	rec := httptest.NewRecorder()
	fb.Serve(rec, req)

	if got := rec.Header().Get("Location"); got != "http://my-site.com/login" {
		t.Errorf("Location = %q, want %q", got, "http://my-site.com/login")
	}
}

// ---------------------------------------------------------------------------
// Set-Cookie 头重写测试
// ---------------------------------------------------------------------------

// TestSetFallbackProxy_RewriteSetCookieDomain 验证 Set-Cookie 头中
// 指向上游 host 的 Domain 属性会被移除，使浏览器能接受
// 代理 host 下的 cookie。
func TestSetFallbackProxy_RewriteSetCookieDomain(t *testing.T) {
	fb := newTestFallback(t)
	var upstreamHost string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		// 使用原始的 Set-Cookie 头（而非 http.SetCookie），
		// 以避免标准库在 Domain 属性包含端口号时
		// 将其丢弃。
		w.Header().Add("Set-Cookie",
			"_gh_sess=abc123; Domain="+upstreamHost+"; Path=/; HttpOnly; Secure")
		w.Write([]byte("<html></html>")) //nolint:errcheck //nolint:errcheck
	}))
	defer upstream.Close()
	upstreamHost = upstream.Listener.Addr().String()

	if err := fb.setProxy(upstream.URL, false, nil); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "my-site.com"
	rec := httptest.NewRecorder()
	fb.Serve(rec, req)

	// 解析原始 Set-Cookie 头以验证 Domain 已被移除。
	rawCookies := rec.Result().Header["Set-Cookie"]
	if len(rawCookies) != 1 {
		t.Fatalf("expected 1 Set-Cookie header, got %d", len(rawCookies))
	}
	if strings.Contains(rawCookies[0], "Domain=") {
		t.Errorf("Set-Cookie should not contain Domain attribute\nraw: %s", rawCookies[0])
	}
	// 验证 cookie 的名称/值及其他属性都被保留。
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 parsed cookie, got %d", len(cookies))
	}
	if cookies[0].Name != "_gh_sess" || cookies[0].Value != "abc123" {
		t.Errorf("cookie = %q=%q, want %q=%q", cookies[0].Name, cookies[0].Value, "_gh_sess", "abc123")
	}
	if !cookies[0].HttpOnly {
		t.Error("cookie HttpOnly should be preserved")
	}
	if !cookies[0].Secure {
		t.Error("cookie Secure should be preserved")
	}
}

// TestSetFallbackProxy_RewriteSetCookieDomainWithDot 验证带前导点号的 Domain
// 属性（例如 ".github.com"）同样会被移除。
func TestSetFallbackProxy_RewriteSetCookieDomainWithDot(t *testing.T) {
	fb := newTestFallback(t)
	var upstreamHost string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		// 手动设置一个带前导点号域名的原始 Set-Cookie。
		w.Header().Add("Set-Cookie", "test=val; Domain=."+upstreamHost+"; Path=/; Secure")
		w.Write([]byte("<html></html>")) //nolint:errcheck
	}))
	defer upstream.Close()
	upstreamHost = upstream.Listener.Addr().String()

	if err := fb.setProxy(upstream.URL, false, nil); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "my-site.com"
	rec := httptest.NewRecorder()
	fb.Serve(rec, req)

	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}
	if cookies[0].Domain != "" {
		t.Errorf("cookie Domain = %q, want empty (removed)", cookies[0].Domain)
	}
}

// TestSetFallbackProxy_SetCookieOtherDomainUnchanged 验证 Domain 指向非上游
// host 的 cookie 不会被改动。
func TestSetFallbackProxy_SetCookieOtherDomainUnchanged(t *testing.T) {
	fb := newTestFallback(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Add("Set-Cookie", "test=val; Domain=other.example.com; Path=/")
		w.Write([]byte("<html></html>")) //nolint:errcheck
	}))
	defer upstream.Close()

	if err := fb.setProxy(upstream.URL, false, nil); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "my-site.com"
	rec := httptest.NewRecorder()
	fb.Serve(rec, req)

	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}
	if cookies[0].Domain != "other.example.com" {
		t.Errorf("cookie Domain = %q, want %q (unchanged)", cookies[0].Domain, "other.example.com")
	}
}

// TestSetFallbackProxy_SetCookieNoDomainUnchanged 验证没有 Domain 属性的
// cookie 不会被改动。
func TestSetFallbackProxy_SetCookieNoDomainUnchanged(t *testing.T) {
	fb := newTestFallback(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		http.SetCookie(w, &http.Cookie{
			Name:  "test",
			Value: "val",
			Path:  "/",
		})
		w.Write([]byte("<html></html>")) //nolint:errcheck
	}))
	defer upstream.Close()

	if err := fb.setProxy(upstream.URL, false, nil); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "my-site.com"
	rec := httptest.NewRecorder()
	fb.Serve(rec, req)

	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}
	if cookies[0].Domain != "" {
		t.Errorf("cookie Domain = %q, want empty (already empty)", cookies[0].Domain)
	}
	if cookies[0].Value != "val" {
		t.Errorf("cookie Value = %q, want %q", cookies[0].Value, "val")
	}
}

// ---------------------------------------------------------------------------
// setFallbackProxy 内容重写测试（URL 模式下始终启用）
// ---------------------------------------------------------------------------

// TestSetFallbackProxy_RewriteContent 验证 HTML 响应体中指向
// 上游 host 的绝对 URL 会被重写为面向客户端的
// origin。
func TestSetFallbackProxy_RewriteContent(t *testing.T) {
	fb := newTestFallback(t)
	var upstreamHost string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(`<html><a href="https://` + upstreamHost + `/repo">link</a>` + //nolint:errcheck
			`<turbo-frame src="https://` + upstreamHost + `/repo/releases/expanded_assets/v1">` +
			`</turbo-frame></html>`))
	}))
	defer upstream.Close()
	upstreamHost = upstream.Listener.Addr().String()

	if err := fb.setProxy(upstream.URL, false, nil); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/repo/releases", nil)
	req.Host = "my-site.com"
	rec := httptest.NewRecorder()
	fb.Serve(rec, req)

	// httptest.NewRequest 的 TLS 为 nil，因此 origScheme 默认为 "http"。
	body := rec.Body.String()
	want := "http://my-site.com/repo"
	if !bytes.Contains([]byte(body), []byte(want)) {
		t.Errorf("body does not contain %q\nbody: %s", want, body)
	}
	if bytes.Contains([]byte(body), []byte(upstreamHost)) {
		t.Errorf("body should not contain upstream host %q\nbody: %s", upstreamHost, body)
	}
}

// TestSetFallbackProxy_RewriteContentCSP 验证
// Content-Security-Policy 头会被重写，把其中的上游 URL
// 替换为面向客户端的 origin。
func TestSetFallbackProxy_RewriteContentCSP(t *testing.T) {
	fb := newTestFallback(t)
	var upstreamHost string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; connect-src 'self' https://"+upstreamHost+" api."+upstreamHost)
		w.Write([]byte("<html></html>")) //nolint:errcheck
	}))
	defer upstream.Close()
	upstreamHost = upstream.Listener.Addr().String()

	if err := fb.setProxy(upstream.URL, false, nil); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "my-site.com"
	rec := httptest.NewRecorder()
	fb.Serve(rec, req)

	csp := rec.Header().Get("Content-Security-Policy")
	if bytes.Contains([]byte(csp), []byte("https://"+upstreamHost)) {
		t.Errorf("CSP should not contain https://%s\ncsp: %s", upstreamHost, csp)
	}
	// httptest.NewRequest 的 TLS 为 nil → origScheme = "http"。
	if !bytes.Contains([]byte(csp), []byte("http://my-site.com")) {
		t.Errorf("CSP should contain http://my-site.com\ncsp: %s", csp)
	}
	// 子域引用应被保留（不被替换）。
	if !bytes.Contains([]byte(csp), []byte("api."+upstreamHost)) {
		t.Errorf("CSP should still contain api.%s\ncsp: %s", upstreamHost, csp)
	}
}

// TestSetFallbackProxy_RewriteCSPBareHost 验证 CSP 中不带 scheme 前缀的
// 裸主机（bare-host）源表达式（例如
// "github.com/assets-cdn/worker/"）会被重写为面向客户端的 host。
// GitHub 的 worker-src 指令使用无 scheme 的路径，
// 因此需要这一处理。
func TestSetFallbackProxy_RewriteCSPBareHost(t *testing.T) {
	fb := newTestFallback(t)
	var upstreamHost string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		// 模拟 GitHub 风格的 CSP，在 worker-src 中使用裸主机路径。
		w.Header().Set("Content-Security-Policy",
			"worker-src "+upstreamHost+"/assets-cdn/worker/ "+upstreamHost+"/assets/ gist."+upstreamHost+"/assets-cdn/worker/")
		w.Write([]byte("<html></html>")) //nolint:errcheck
	}))
	defer upstream.Close()
	upstreamHost = upstream.Listener.Addr().String()

	if err := fb.setProxy(upstream.URL, false, nil); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "my-site.com"
	rec := httptest.NewRecorder()
	fb.Serve(rec, req)

	csp := rec.Header().Get("Content-Security-Policy")
	// 裸上游主机应被替换为面向客户端的 host。
	// 检查不残留带空格前缀的上游主机路径（空格确保匹配的是独立 token，
	// 而不是 "gist." 的子串）。
	if strings.Contains(csp, " "+upstreamHost+"/assets-cdn/worker/") {
		t.Errorf("CSP should not contain bare %q/assets-cdn/worker/\ncsp: %s", upstreamHost, csp)
	}
	if !strings.Contains(csp, "my-site.com/assets-cdn/worker/") {
		t.Errorf("CSP should contain my-site.com/assets-cdn/worker/\ncsp: %s", csp)
	}
	if !strings.Contains(csp, "my-site.com/assets/") {
		t.Errorf("CSP should contain my-site.com/assets/\ncsp: %s", csp)
	}
	// 子域引用应被保留（不被替换）。
	if !strings.Contains(csp, "gist."+upstreamHost) {
		t.Errorf("CSP should still contain gist.%s\ncsp: %s", upstreamHost, csp)
	}
}

// TestSetFallbackProxy_RewriteCSPMixed 验证同时包含带 scheme 前缀
// 和裸主机形式上游主机的 CSP 都会被正确重写，
// 而其他主机和子域会被保留。
func TestSetFallbackProxy_RewriteCSPMixed(t *testing.T) {
	fb := newTestFallback(t)
	var upstreamHost string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Content-Security-Policy",
			"connect-src 'self' https://"+upstreamHost+" "+upstreamHost+"/api "+
				"api."+upstreamHost+" https://other.example.com")
		w.Write([]byte("<html></html>")) //nolint:errcheck
	}))
	defer upstream.Close()
	upstreamHost = upstream.Listener.Addr().String()

	if err := fb.setProxy(upstream.URL, false, nil); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "my-site.com"
	rec := httptest.NewRecorder()
	fb.Serve(rec, req)

	csp := rec.Header().Get("Content-Security-Policy")
	// 不应残留任何上游主机（子域 api. 除外）。
	if bytes.Contains([]byte(csp), []byte("https://"+upstreamHost)) {
		t.Errorf("CSP should not contain https://%s\ncsp: %s", upstreamHost, csp)
	}
	if bytes.Contains([]byte(csp), []byte(" "+upstreamHost+"/")) {
		t.Errorf("CSP should not contain bare %q/\ncsp: %s", upstreamHost, csp)
	}
	// 面向客户端的 host 应存在。
	if !bytes.Contains([]byte(csp), []byte("my-site.com")) {
		t.Errorf("CSP should contain my-site.com\ncsp: %s", csp)
	}
	// 子域和其他主机应被保留。
	if !bytes.Contains([]byte(csp), []byte("api."+upstreamHost)) {
		t.Errorf("CSP should still contain api.%s\ncsp: %s", upstreamHost, csp)
	}
	if !bytes.Contains([]byte(csp), []byte("other.example.com")) {
		t.Errorf("CSP should still contain other.example.com\ncsp: %s", csp)
	}
}

// TestSetFallbackProxy_RewriteContentGzip 验证 gzip 压缩的 HTML 响应会被
// 解压并正确重写。
func TestSetFallbackProxy_RewriteContentGzip(t *testing.T) {
	fb := newTestFallback(t)
	var upstreamHost string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 模拟一个忽略 Accept-Encoding: identity、
		// 仍然发送 gzip 的上游。
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Content-Encoding", "gzip")
		gw := gzip.NewWriter(w)
		gw.Write([]byte(`<html><a href="https://` + upstreamHost + `/test">link</a></html>`)) //nolint:errcheck
		gw.Close()                                                                            //nolint:errcheck
	}))
	defer upstream.Close()
	upstreamHost = upstream.Listener.Addr().String()

	if err := fb.setProxy(upstream.URL, false, nil); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "my-site.com"
	rec := httptest.NewRecorder()
	fb.Serve(rec, req)

	// Content-Encoding 应被移除（重写后发送未压缩的内容）。
	if ce := rec.Header().Get("Content-Encoding"); ce != "" {
		t.Errorf("Content-Encoding = %q, want empty", ce)
	}
	body := rec.Body.String()
	// httptest.NewRequest 的 TLS 为 nil → origScheme = "http"。
	if !bytes.Contains([]byte(body), []byte("http://my-site.com/test")) {
		t.Errorf("body should contain rewritten URL\nbody: %s", body)
	}
	if bytes.Contains([]byte(body), []byte(upstreamHost)) {
		t.Errorf("body should not contain upstream host %q\nbody: %s", upstreamHost, body)
	}
}

// TestSetFallbackProxy_RewriteContentNonHTML 验证非 HTML 响应会原样透传
// （只有 HTML 会被重写）。
func TestSetFallbackProxy_RewriteContentNonHTML(t *testing.T) {
	fb := newTestFallback(t)
	var upstreamHost string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"url":"https://` + upstreamHost + `/api"}`)) //nolint:errcheck
	}))
	defer upstream.Close()
	upstreamHost = upstream.Listener.Addr().String()

	if err := fb.setProxy(upstream.URL, false, nil); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api", nil)
	req.Host = "my-site.com"
	rec := httptest.NewRecorder()
	fb.Serve(rec, req)

	// JSON 不应被重写。
	if bytes.Contains(rec.Body.Bytes(), []byte("my-site.com")) {
		t.Errorf("non-HTML body should not be rewritten\nbody: %s", rec.Body.String())
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte(upstreamHost)) {
		t.Errorf("non-HTML body should contain upstream host\nbody: %s", rec.Body.String())
	}
}

// TestSetFallbackProxy_RewriteContentAcceptEncoding_ClientGzip 验证当客户端
// 接受 gzip 时，上游收到的是 "identity, gzip"。
func TestSetFallbackProxy_RewriteContentAcceptEncoding_ClientGzip(t *testing.T) {
	fb := newTestFallback(t)
	var gotAE string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAE = r.Header.Get("Accept-Encoding")
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html></html>")) //nolint:errcheck
	}))
	defer upstream.Close()

	if err := fb.setProxy(upstream.URL, false, nil); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "my-site.com"
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	rec := httptest.NewRecorder()
	fb.Serve(rec, req)

	if gotAE != "identity, gzip" {
		t.Errorf("upstream received Accept-Encoding %q, want %q", gotAE, "identity, gzip")
	}
}

// TestSetFallbackProxy_RewriteContentAcceptEncoding_ClientNoGzip 验证当客户端
// 不接受 gzip 时，上游只收到 "identity"。
func TestSetFallbackProxy_RewriteContentAcceptEncoding_ClientNoGzip(t *testing.T) {
	fb := newTestFallback(t)
	var gotAE string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAE = r.Header.Get("Accept-Encoding")
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html></html>")) //nolint:errcheck
	}))
	defer upstream.Close()

	if err := fb.setProxy(upstream.URL, false, nil); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "my-site.com"
	// 没有 Accept-Encoding 头 → 客户端不接受 gzip。
	rec := httptest.NewRecorder()
	fb.Serve(rec, req)

	if gotAE != "identity" {
		t.Errorf("upstream received Accept-Encoding %q, want %q", gotAE, "identity")
	}
}

// TestSetFallbackProxy_RewriteContent_RecompressGzip 验证当客户端接受 gzip 时，
// 重写后的 HTML 响应会用 gzip 重新压缩，并把 Content-Encoding 头设置为
// "gzip"。
func TestSetFallbackProxy_RewriteContent_RecompressGzip(t *testing.T) {
	fb := newTestFallback(t)
	var upstreamHost string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><a href="https://` + upstreamHost + `/test">link</a></html>`)) //nolint:errcheck
	}))
	defer upstream.Close()
	upstreamHost = upstream.Listener.Addr().String()

	if err := fb.setProxy(upstream.URL, false, nil); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "my-site.com"
	req.Header.Set("Accept-Encoding", "gzip")
	rec := httptest.NewRecorder()
	fb.Serve(rec, req)

	if ce := rec.Header().Get("Content-Encoding"); ce != "gzip" {
		t.Errorf("Content-Encoding = %q, want %q", ce, "gzip")
	}

	// 解压响应体并验证重写后的 URL。
	gr, err := gzip.NewReader(rec.Body)
	if err != nil {
		t.Fatalf("gzip reader: %v", err)
	}
	body, _ := io.ReadAll(gr)
	gr.Close() //nolint:errcheck
	if !bytes.Contains(body, []byte("http://my-site.com/test")) {
		t.Errorf("decompressed body should contain rewritten URL\nbody: %s", body)
	}
	if bytes.Contains(body, []byte(upstreamHost)) {
		t.Errorf("body should not contain upstream host %q\nbody: %s", upstreamHost, body)
	}
}

// TestSetFallbackProxy_RewriteContent_NoRecompressWhenClientNoGzip
// 验证当客户端不接受 gzip 时，即使上游返回了 gzip，
// 重写后的 HTML 也会以未压缩形式发送。
func TestSetFallbackProxy_RewriteContent_NoRecompressWhenClientNoGzip(t *testing.T) {
	fb := newTestFallback(t)
	var upstreamHost string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Content-Encoding", "gzip")
		gw := gzip.NewWriter(w)
		gw.Write([]byte(`<html><a href="https://` + upstreamHost + `/test">link</a></html>`)) //nolint:errcheck
		gw.Close()                                                                            //nolint:errcheck
	}))
	defer upstream.Close()
	upstreamHost = upstream.Listener.Addr().String()

	if err := fb.setProxy(upstream.URL, false, nil); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "my-site.com"
	// 没有 Accept-Encoding → 客户端不接受 gzip。
	rec := httptest.NewRecorder()
	fb.Serve(rec, req)

	if ce := rec.Header().Get("Content-Encoding"); ce != "" {
		t.Errorf("Content-Encoding = %q, want empty (client does not accept gzip)", ce)
	}
	body := rec.Body.String()
	if !bytes.Contains([]byte(body), []byte("http://my-site.com/test")) {
		t.Errorf("body should contain rewritten URL\nbody: %s", body)
	}
}

// TestClientAcceptsGzip 验证 clientAcceptsGzip 辅助函数。
func TestClientAcceptsGzip(t *testing.T) {
	tests := []struct {
		ae   string
		want bool
	}{
		{"", false},
		{"identity", false},
		{"gzip", true},
		{"gzip, deflate", true},
		{"deflate, gzip", true},
		{"gzip;q=0", false},
		{"gzip;q=0.0", false},
		{"gzip;q=0.1", true},
		{"gzip;q=1", true},
		{"gzip;q=1.0", true},
		{"*", true},
		{"*;q=0", false},
		{"br", false},
		{"deflate", false},
		{"  gzip  ", true},
	}
	for _, tt := range tests {
		if got := clientAcceptsGzip(tt.ae); got != tt.want {
			t.Errorf("clientAcceptsGzip(%q) = %v, want %v", tt.ae, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Origin / Referer 请求头重写测试
// ---------------------------------------------------------------------------

// TestSetFallbackProxy_RewriteOrigin 验证 POST 请求的 Origin 头
// 会从面向客户端的 host 重写为上游 host，
// 从而使 Rails 的 CSRF 防护接受该请求。
func TestSetFallbackProxy_RewriteOrigin(t *testing.T) {
	fb := newTestFallback(t)
	var gotOrigin string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotOrigin = r.Header.Get("Origin")
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html></html>")) //nolint:errcheck
	}))
	defer upstream.Close()
	upstreamHost := upstream.Listener.Addr().String()

	if err := fb.setProxy(upstream.URL, false, nil); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/session", nil)
	req.Host = "my-site.com"
	req.Header.Set("Origin", "http://my-site.com")
	rec := httptest.NewRecorder()
	fb.Serve(rec, req)

	want := "http://" + upstreamHost
	if gotOrigin != want {
		t.Errorf("upstream received Origin %q, want %q", gotOrigin, want)
	}
}

// TestSetFallbackProxy_RewriteReferer 验证 Referer 头会从
// 面向客户端的 host 重写为上游 host，
// 并保留路径。
func TestSetFallbackProxy_RewriteReferer(t *testing.T) {
	fb := newTestFallback(t)
	var gotReferer string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotReferer = r.Header.Get("Referer")
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html></html>")) //nolint:errcheck
	}))
	defer upstream.Close()
	upstreamHost := upstream.Listener.Addr().String()

	if err := fb.setProxy(upstream.URL, false, nil); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/session", nil)
	req.Host = "my-site.com"
	req.Header.Set("Referer", "http://my-site.com/login")
	rec := httptest.NewRecorder()
	fb.Serve(rec, req)

	want := "http://" + upstreamHost + "/login"
	if gotReferer != want {
		t.Errorf("upstream received Referer %q, want %q", gotReferer, want)
	}
}

// TestSetFallbackProxy_OtherHostOriginUnchanged 验证指向非面向客户端 host 的
// Origin 头不会被改动。
func TestSetFallbackProxy_OtherHostOriginUnchanged(t *testing.T) {
	fb := newTestFallback(t)
	var gotOrigin string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotOrigin = r.Header.Get("Origin")
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html></html>")) //nolint:errcheck
	}))
	defer upstream.Close()

	if err := fb.setProxy(upstream.URL, false, nil); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/session", nil)
	req.Host = "my-site.com"
	req.Header.Set("Origin", "http://other.example.com")
	rec := httptest.NewRecorder()
	fb.Serve(rec, req)

	if gotOrigin != "http://other.example.com" {
		t.Errorf("upstream received Origin %q, want %q (unchanged)", gotOrigin, "http://other.example.com")
	}
}

// TestSetFallbackProxy_NoOriginNoError 验证没有 Origin 或 Referer 头的请求
// 也能无错误地处理。
func TestSetFallbackProxy_NoOriginNoError(t *testing.T) {
	fb := newTestFallback(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html></html>")) //nolint:errcheck
	}))
	defer upstream.Close()

	if err := fb.setProxy(upstream.URL, false, nil); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/session", nil)
	req.Host = "my-site.com"
	rec := httptest.NewRecorder()
	fb.Serve(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

// ---------------------------------------------------------------------------
// CDN 域名代理测试
// ---------------------------------------------------------------------------

// TestSetFallbackProxy_CDNRoute 验证对 /__cdn__/<host>/<path> 的请求
// 会以正确的 Host 头代理到
// https://<host>/<path>。
func TestSetFallbackProxy_CDNRoute(t *testing.T) {
	fb := newTestFallback(t)
	var gotHost, gotPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("upstream")) //nolint:errcheck
	}))
	defer upstream.Close()

	cdnServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Host
		gotPath = r.URL.Path
		w.Write([]byte("cdn-content")) //nolint:errcheck
	}))
	defer cdnServer.Close()
	cdnHost := cdnServer.Listener.Addr().String()

	if err := fb.setProxy(upstream.URL, false, []string{cdnHost}); err != nil {
		t.Fatal(err)
	}

	// 覆盖代理的 Transport，跳过对测试所用自签名证书的 TLS 校验。
	// 实例是测试私有的，因此不需要还原。
	fb.proxy.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	// 通过 /__cdn__/ 前缀路径发起请求。
	req := httptest.NewRequest(http.MethodGet, cdnPathPrefix+cdnHost+"/assets/foo.css", nil)
	req.Host = "my-site.com"
	rec := httptest.NewRecorder()
	fb.Serve(rec, req)

	if gotHost != cdnHost {
		t.Errorf("CDN received Host %q, want %q", gotHost, cdnHost)
	}
	if gotPath != "/assets/foo.css" {
		t.Errorf("CDN received Path %q, want %q", gotPath, "/assets/foo.css")
	}
}

// TestSetFallbackProxy_CDNRouteDisallowedHost 验证对不在允许列表中
// 的主机的 /__cdn__/ 请求不会被当作 CDN 请求代理
// （它会回落到主上游）。
func TestSetFallbackProxy_CDNRouteDisallowedHost(t *testing.T) {
	fb := newTestFallback(t)
	var gotPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Write([]byte("upstream")) //nolint:errcheck
	}))
	defer upstream.Close()

	if err := fb.setProxy(upstream.URL, false, []string{"allowed.cdn.com"}); err != nil {
		t.Fatal(err)
	}

	// 向不允许的 CDN 主机发起请求。
	req := httptest.NewRequest(http.MethodGet, cdnPathPrefix+"evil.cdn.com/assets/foo.css", nil)
	req.Host = "my-site.com"
	rec := httptest.NewRecorder()
	fb.Serve(rec, req)

	// 应带着 /__cdn__/ 路径路由到主上游
	// （主机不在允许集合中，因此 routeCDN 返回 false，走正常的
	// 上游路由逻辑）。
	if gotPath != cdnPathPrefix+"evil.cdn.com/assets/foo.css" {
		t.Errorf("upstream received Path %q, want %q (passed through)", gotPath, cdnPathPrefix+"evil.cdn.com/assets/foo.css")
	}
}

// TestSetFallbackProxy_CDNHTMLRewrite 验证 HTML 响应体中指向
// 已配置 CDN 域名的绝对 URL 会被重写为
// /__cdn__/<host> 前缀形式。
func TestSetFallbackProxy_CDNHTMLRewrite(t *testing.T) {
	fb := newTestFallback(t)
	var upstreamHost string
	cdnHost := "cdn.example.com"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><link rel="stylesheet" href="https://` + cdnHost + `/assets/foo.css">` + //nolint:errcheck
			`<script src="https://` + cdnHost + `/assets/bar.js"></script></html>`))
	}))
	defer upstream.Close()
	upstreamHost = upstream.Listener.Addr().String()
	_ = upstreamHost

	if err := fb.setProxy(upstream.URL, false, []string{cdnHost}); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "my-site.com"
	rec := httptest.NewRecorder()
	fb.Serve(rec, req)

	body := rec.Body.String()
	wantPrefix := "http://my-site.com" + cdnPathPrefix + cdnHost
	if !strings.Contains(body, wantPrefix+"/assets/foo.css") {
		t.Errorf("body should contain %q/assets/foo.css\nbody: %s", wantPrefix, body)
	}
	if !strings.Contains(body, wantPrefix+"/assets/bar.js") {
		t.Errorf("body should contain %q/assets/bar.js\nbody: %s", wantPrefix, body)
	}
	// 原始 CDN URL 不应出现。
	if strings.Contains(body, "https://"+cdnHost) {
		t.Errorf("body should not contain https://%s\nbody: %s", cdnHost, body)
	}
}

// TestSetFallbackProxy_CDNCSPRewrite 验证引用已配置 CDN 域名的
// CSP 源表达式会被重写为
// /__cdn__/ 前缀形式。
func TestSetFallbackProxy_CDNCSPRewrite(t *testing.T) {
	fb := newTestFallback(t)
	cdnHost := "cdn.example.com"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; style-src 'self' https://"+cdnHost+" "+cdnHost+"/assets/; script-src "+cdnHost)
		w.Write([]byte("<html></html>")) //nolint:errcheck
	}))
	defer upstream.Close()

	if err := fb.setProxy(upstream.URL, false, []string{cdnHost}); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "my-site.com"
	rec := httptest.NewRecorder()
	fb.Serve(rec, req)

	csp := rec.Header().Get("Content-Security-Policy")
	// CDN 主机应被重写为 /__cdn__/ 前缀形式。
	wantCSPHost := "my-site.com" + cdnPathPrefix + cdnHost
	if !strings.Contains(csp, "http://"+wantCSPHost) {
		t.Errorf("CSP should contain http://%s\ncsp: %s", wantCSPHost, csp)
	}
	// 原始 CDN 主机有意与重写后的形式一起保留，
	// 这样 JS 动态构造的 CDN URL 不会被拦截。
	// 这里只验证重写后的形式存在，
	// 不断言原始形式不存在。
}

// TestSetFallbackProxy_CDNNotConfigured 验证未配置任何 CDN 域名时，
// 指向外部主机的 HTML URL 不会被重写
// （保持原样）。
func TestSetFallbackProxy_CDNNotConfigured(t *testing.T) {
	fb := newTestFallback(t)
	cdnHost := "cdn.example.com"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><link href="https://` + cdnHost + `/foo.css"></html>`)) //nolint:errcheck
	}))
	defer upstream.Close()

	// 未配置任何 CDN 域名。
	if err := fb.setProxy(upstream.URL, false, nil); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "my-site.com"
	rec := httptest.NewRecorder()
	fb.Serve(rec, req)

	body := rec.Body.String()
	// CDN URL 应保持不变。
	if !strings.Contains(body, "https://"+cdnHost+"/foo.css") {
		t.Errorf("body should contain unchanged CDN URL\nbody: %s", body)
	}
}

// TestSetFallbackProxy_CDNSubdomainRoute 验证对已配置 CDN 域名的子域的
// /__cdn__/ 请求能被正确路由（提取子域主机
// 作为上游主机）。
func TestSetFallbackProxy_CDNSubdomainRoute(t *testing.T) {
	fb := newTestFallback(t)
	cdnParent := "githubassets.com"
	cdnSub := "github.githubassets.com"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("upstream")) //nolint:errcheck
	}))
	defer upstream.Close()

	if err := fb.setProxy(upstream.URL, false, []string{cdnParent}); err != nil {
		t.Fatal(err)
	}

	// 使用自定义 Transport 捕获目标主机而不真正建立连接
	// （测试环境中该子域无法通过 DNS 解析）。
	var capturedHost string
	fb.proxy.Transport = &roundTripFunc{
		fn: func(req *http.Request) (*http.Response, error) {
			capturedHost = req.URL.Host
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"text/html"}},
				Body:       io.NopCloser(bytes.NewReader([]byte("<html></html>"))),
				Request:    req,
			}, nil
		},
	}

	req := httptest.NewRequest(http.MethodGet, cdnPathPrefix+cdnSub+"/assets/foo.css", nil)
	req.Host = "my-site.com"
	rec := httptest.NewRecorder()
	fb.Serve(rec, req)

	if capturedHost != cdnSub {
		t.Errorf("upstream host = %q, want %q (subdomain)", capturedHost, cdnSub)
	}
}

// TestServeFallbackProxyStripsXESHeader 验证 easyss 特有的请求头（x-es）
// 会在请求转发给上游服务前被移除，从而保证代理协议痕迹
// 永远不会泄露给回退站点。
func TestServeFallbackProxyStripsXESHeader(t *testing.T) {
	fb := newTestFallback(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	if err := fb.setProxy(upstream.URL, false, nil); err != nil {
		t.Fatal(err)
	}

	var captured *http.Request
	fb.proxy.Transport = &roundTripFunc{
		fn: func(req *http.Request) (*http.Response, error) {
			captured = req
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"text/html"}},
				Body:       io.NopCloser(bytes.NewReader([]byte("<html></html>"))),
				Request:    req,
			}, nil
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/v3/tcp", nil)
	req.Host = "my-site.com"
	req.Header.Set("x-es", "UQ8k8i0v8JX5m6pQ2lC1AQ") // 22 字符的 base64url salt
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0) Chrome/131.0.0.0")
	rec := httptest.NewRecorder()
	fb.Serve(rec, req)

	if captured == nil {
		t.Fatal("expected upstream request to be captured")
	}
	if got := captured.Header.Get("x-es"); got != "" {
		t.Errorf("x-es header leaked to upstream: %q", got)
	}
	if got := captured.Header.Get("User-Agent"); got == "" {
		t.Error("non-proxy headers should be preserved")
	}
}

// roundTripFunc 是测试用的辅助 Transport，
// 捕获请求而不建立真实网络连接。
type roundTripFunc struct {
	fn func(*http.Request) (*http.Response, error)
}

func (rt *roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return rt.fn(req)
}

// TestSetFallbackProxy_CDNSubdomainHTMLRewrite 验证指向已配置 CDN 域名
// 的子域的绝对 URL 会被重写为
// /__cdn__/<subdomain-host> 形式。
func TestSetFallbackProxy_CDNSubdomainHTMLRewrite(t *testing.T) {
	fb := newTestFallback(t)
	cdnParent := "githubassets.com"
	cdnSub := "github.githubassets.com"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><link rel="stylesheet" href="https://` + cdnSub + `/assets/foo.css">` + //nolint:errcheck
			`<link rel="stylesheet" href="https://` + cdnParent + `/assets/bar.css"></html>`))
	}))
	defer upstream.Close()

	// 只配置父域名。
	if err := fb.setProxy(upstream.URL, false, []string{cdnParent}); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "my-site.com"
	rec := httptest.NewRecorder()
	fb.Serve(rec, req)

	body := rec.Body.String()
	// 子域 URL 应使用完整的子域主机名进行重写。
	wantSub := "http://my-site.com" + cdnPathPrefix + cdnSub + "/assets/foo.css"
	if !strings.Contains(body, wantSub) {
		t.Errorf("body should contain %q\nbody: %s", wantSub, body)
	}
	// 父域 URL 也应被重写。
	wantParent := "http://my-site.com" + cdnPathPrefix + cdnParent + "/assets/bar.css"
	if !strings.Contains(body, wantParent) {
		t.Errorf("body should contain %q\nbody: %s", wantParent, body)
	}
	// 原始 URL 不应出现。
	if strings.Contains(body, "https://"+cdnSub) {
		t.Errorf("body should not contain https://%s\nbody: %s", cdnSub, body)
	}
	if strings.Contains(body, "https://"+cdnParent) {
		t.Errorf("body should not contain https://%s\nbody: %s", cdnParent, body)
	}
}

// TestSetFallbackProxy_CDNNonMatchingSubdomain 验证只是以配置的 CDN 域名
// 字符串结尾、但并非真正子域的主机不会被匹配。
// 例如 "notgithubassets.com" 不应匹配
// "githubassets.com"。
func TestSetFallbackProxy_CDNNonMatchingSubdomain(t *testing.T) {
	fb := newTestFallback(t)
	cdnParent := "githubassets.com"
	fakeHost := "notgithubassets.com"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><link href="https://` + fakeHost + `/foo.css"></html>`)) //nolint:errcheck
	}))
	defer upstream.Close()

	if err := fb.setProxy(upstream.URL, false, []string{cdnParent}); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "my-site.com"
	rec := httptest.NewRecorder()
	fb.Serve(rec, req)

	body := rec.Body.String()
	// 伪主机的 URL 不应被重写。
	if !strings.Contains(body, "https://"+fakeHost+"/foo.css") {
		t.Errorf("body should contain unchanged %q URL\nbody: %s", fakeHost, body)
	}
	if strings.Contains(body, cdnPathPrefix+fakeHost) {
		t.Errorf("body should not contain /__cdn__/%s\nbody: %s", fakeHost, body)
	}
}

// TestSetFallbackProxy_CDNCSPSubdomainRewrite 验证引用已配置 CDN 域名的
// 子域的 CSP 源表达式会被重写为 /__cdn__/ 前缀形式。
// 这是 "blocked:csp" 问题的关键修复：GitHub 的 CSP 引用
// "github.githubassets.com"，而只配置了
// "githubassets.com"。
func TestSetFallbackProxy_CDNCSPSubdomainRewrite(t *testing.T) {
	fb := newTestFallback(t)
	cdnParent := "githubassets.com"
	cdnSub := "github.githubassets.com"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		// 模拟 GitHub 风格的含子域引用的 CSP。
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; style-src 'self' https://"+cdnSub+" "+cdnSub+"/assets/ "+
				cdnSub+" https://"+cdnParent+" "+cdnParent+"/assets/")
		w.Write([]byte("<html></html>")) //nolint:errcheck
	}))
	defer upstream.Close()

	// 只配置父域名。
	if err := fb.setProxy(upstream.URL, false, []string{cdnParent}); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "my-site.com"
	rec := httptest.NewRecorder()
	fb.Serve(rec, req)

	csp := rec.Header().Get("Content-Security-Policy")
	// 子域引用应被重写为 /__cdn__/ 前缀形式。
	wantSubScheme := "http://my-site.com" + cdnPathPrefix + cdnSub
	if !strings.Contains(csp, wantSubScheme) {
		t.Errorf("CSP should contain %q\ncsp: %s", wantSubScheme, csp)
	}
	// 裸子域也应被重写。
	wantSubBare := "my-site.com" + cdnPathPrefix + cdnSub
	if !strings.Contains(csp, wantSubBare+"/assets/") {
		t.Errorf("CSP should contain %q/assets/\ncsp: %s", wantSubBare, csp)
	}
	// 父域引用也应被重写。
	wantParentScheme := "http://my-site.com" + cdnPathPrefix + cdnParent
	if !strings.Contains(csp, wantParentScheme) {
		t.Errorf("CSP should contain %q\ncsp: %s", wantParentScheme, csp)
	}
	// 原始 CDN 主机有意与重写后的形式一起保留，
	// 这样 JS 动态构造的 URL 不会被 CSP 拦截。
	// 这里只验证重写后的形式存在。
}

// TestSetFallbackProxy_CSPRewrittenEvenWhenBodyUnreadable 验证即使
// 响应体无法读取（例如 Content-Encoding 为不支持的 br）时，
// Content-Security-Policy 头仍会被重写。这是 "blocked:csp" 问题的
// 关键修复：此前在到达 CSP 重写代码之前就因读取响应体失败
// 而跳过了 CSP 重写。
func TestSetFallbackProxy_CSPRewrittenEvenWhenBodyUnreadable(t *testing.T) {
	fb := newTestFallback(t)
	cdnParent := "githubassets.com"
	cdnSub := "github.githubassets.com"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		// 返回代理无法解压的 br 编码，使 rewriteResponseBody 跳过
		// 响应体处理。
		w.Header().Set("Content-Encoding", "br")
		w.Header().Set("Content-Security-Policy",
			"default-src 'none'; style-src 'unsafe-inline' "+cdnSub+" https://"+cdnSub+
				"; script-src "+cdnSub)
		w.Write([]byte("some brotli content that cannot be decompressed")) //nolint:errcheck
	}))
	defer upstream.Close()

	if err := fb.setProxy(upstream.URL, false, []string{cdnParent}); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "my-site.com"
	rec := httptest.NewRecorder()
	fb.Serve(rec, req)

	csp := rec.Header().Get("Content-Security-Policy")
	// 即使响应体无法读取（br 编码），CSP 也应被重写，从而允许 /__cdn__/
	// 路径。
	if !strings.Contains(csp, "my-site.com"+cdnPathPrefix+cdnSub) {
		t.Errorf("CSP should contain my-site.com%s%s\ncsp: %s", cdnPathPrefix, cdnSub, csp)
	}
}

// TestSetFallbackProxy_CDNCSPTrailingSlash 验证 CSP 中不带路径的裸 CDN
// 主机引用会被重写为带末尾 "/" 的形式，使 CSP 的路径匹配允许
// /__cdn__/<host>/ 下的子路径。如果没有末尾的 "/"，CSP 只会
// 精确匹配该路径，从而阻止子资源的加载
// （例如 /__cdn__/<host>/assets/foo.css 上的 CSS）。
func TestSetFallbackProxy_CDNCSPTrailingSlash(t *testing.T) {
	fb := newTestFallback(t)
	cdnParent := "githubassets.com"
	cdnSub := "github.githubassets.com"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		// 使用裸主机（无路径）的 CSP —— 重写后应带末尾 "/"。
		w.Header().Set("Content-Security-Policy",
			"style-src 'unsafe-inline' "+cdnSub+"; script-src https://"+cdnSub)
		w.Write([]byte("<html></html>")) //nolint:errcheck
	}))
	defer upstream.Close()

	if err := fb.setProxy(upstream.URL, false, []string{cdnParent}); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "my-site.com"
	rec := httptest.NewRecorder()
	fb.Serve(rec, req)

	csp := rec.Header().Get("Content-Security-Policy")
	// 裸主机应被重写为带末尾 "/" 的形式，使子路径能匹配。
	wantBare := "my-site.com" + cdnPathPrefix + cdnSub + "/"
	if !strings.Contains(csp, wantBare) {
		t.Errorf("CSP should contain %q (with trailing /)\ncsp: %s", wantBare, csp)
	}
	// 带 scheme 前缀的形式也应有末尾 "/"。
	wantScheme := "http://my-site.com" + cdnPathPrefix + cdnSub + "/"
	if !strings.Contains(csp, wantScheme) {
		t.Errorf("CSP should contain %q (with trailing /)\ncsp: %s", wantScheme, csp)
	}
}

// TestSetFallbackProxy_NonRewritableContentType 验证除 HTML 外的内容类型
// （例如 JavaScript、JSON）不会被重写，以避免在响应体扫描上浪费
// CPU：对 JS 而言该扫描不可靠（URL 是动态构造的），
// 对 JSON/图片而言又没必要。
func TestSetFallbackProxy_NonRewritableContentType(t *testing.T) {
	fb := newTestFallback(t)
	cdnHost := "github.githubassets.com"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.Write([]byte(`fetch("https://` + cdnHost + `/data.js");`)) //nolint:errcheck
	}))
	defer upstream.Close()

	if err := fb.setProxy(upstream.URL, false, []string{"githubassets.com"}); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/assets/app.js", nil)
	req.Host = "my-site.com"
	rec := httptest.NewRecorder()
	fb.Serve(rec, req)

	body := rec.Body.String()
	// JavaScript 不应被重写 —— 保留原始 URL。
	if !strings.Contains(body, "https://"+cdnHost) {
		t.Errorf("JS body should preserve original URL (not rewritten)\nbody: %s", body)
	}
}

// TestSetFallbackProxy_CDNLocationRewrite 验证从主上游到 CDN 域名的
// 3xx 重定向（例如 GitHub 的 /raw/ → raw.githubusercontent.com）
// 会被重写为 /__cdn__/<host>/<path>，使浏览器能通过代理
// 跟随该重定向。
func TestSetFallbackProxy_CDNLocationRewrite(t *testing.T) {
	fb := newTestFallback(t)
	cdnHost := "raw.githubusercontent.com"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 模拟 GitHub 把 /raw/ 重定向到 raw.githubusercontent.com
		w.Header().Set("Location", "https://"+cdnHost+"/nange/easyss/master/assets/img/tray2.png")
		w.WriteHeader(http.StatusMovedPermanently)
	}))
	defer upstream.Close()

	if err := fb.setProxy(upstream.URL, false, []string{"githubusercontent.com"}); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/nange/easyss/raw/master/assets/img/tray2.png", nil)
	req.Host = "my-site.com"
	rec := httptest.NewRecorder()
	fb.Serve(rec, req)

	want := "http://my-site.com" + cdnPathPrefix + cdnHost + "/nange/easyss/master/assets/img/tray2.png"
	if got := rec.Header().Get("Location"); got != want {
		t.Errorf("Location = %q, want %q", got, want)
	}
}

// TestSetFallbackProxy_CDNLocationNotRewrittenWhenNotConfigured
// 验证当主机不在已配置的 CDN 域名中时，
// 指向类 CDN 主机的重定向不会被重写。
func TestSetFallbackProxy_CDNLocationNotRewrittenWhenNotConfigured(t *testing.T) {
	fb := newTestFallback(t)
	cdnHost := "raw.githubusercontent.com"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "https://"+cdnHost+"/some/path")
		w.WriteHeader(http.StatusFound)
	}))
	defer upstream.Close()

	// 只配置了 githubassets.com，而不是 githubusercontent.com。
	if err := fb.setProxy(upstream.URL, false, []string{"githubassets.com"}); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "my-site.com"
	rec := httptest.NewRecorder()
	fb.Serve(rec, req)

	// Location 应原样透传。
	want := "https://" + cdnHost + "/some/path"
	if got := rec.Header().Get("Location"); got != want {
		t.Errorf("Location = %q, want %q (unchanged)", got, want)
	}
}
