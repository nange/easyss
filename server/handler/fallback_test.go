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

	req := httptest.NewRequest(http.MethodGet, "/style", nil)
	rec := httptest.NewRecorder()
	fb.Serve(rec, req)
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

	// 空目录回落到自动生成的页面。
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

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	fb.Serve(rec, req)
	if rec.Body.String() != "<h1>Dir Home</h1>" {
		t.Errorf("got %q, want dir mode %q", rec.Body.String(), "<h1>Dir Home</h1>")
	}
}

func TestSetFallbackProxy_EmptyURL(t *testing.T) {
	fb := newTestFallback(t)
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
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("proxy-response")) //nolint:errcheck
	}))
	defer upstream.Close()

	if err := fb.setProxy(upstream.URL, false, nil); err != nil {
		t.Fatal(err)
	}

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

	if rec.Body.String() != "proxy-response" {
		t.Errorf("got %q, want %q", rec.Body.String(), "proxy-response")
	}
}

func TestSetFallbackTarget_Empty(t *testing.T) {
	fb := newTestFallback(t)
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

	// 重置后必须回到内置生成页（带 ETag 等真实性头）。
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

// 转发给上游的 Host 必须是上游自己的：否则 GitHub 这类上游会 301 到它的规范域名。
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

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "my-site.com"
	rec := httptest.NewRecorder()
	fb.Serve(rec, req)

	want := upstream.Listener.Addr().String()
	if gotHost != want {
		t.Errorf("upstream received Host %q, want %q", gotHost, want)
	}
}

// 指向上游 host 的 3xx Location 要重写回客户端的 host。
func TestSetFallbackProxy_RewriteLocation(t *testing.T) {
	fb := newTestFallback(t)
	var upstreamHost string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

// preserveHost 时原样转发客户端的 Host，本地 nginx 靠 server_name 做虚拟主机路由。
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

// preserveHost 下上游按 $host 重定向到自身监听地址时，Location 仍要改写成客户端 host。
func TestSetFallbackProxy_PreserveHostLocationRewrite(t *testing.T) {
	fb := newTestFallback(t)
	var upstreamHost string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

// Domain 带端口时浏览器会拒收 cookie，所以要整条移除。
func TestSetFallbackProxy_RewriteSetCookieDomain(t *testing.T) {
	fb := newTestFallback(t)
	var upstreamHost string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		// 用原始 Set-Cookie 头：http.SetCookie 会丢弃 Domain 里带端口的属性。
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

	rawCookies := rec.Result().Header["Set-Cookie"]
	if len(rawCookies) != 1 {
		t.Fatalf("expected 1 Set-Cookie header, got %d", len(rawCookies))
	}
	if strings.Contains(rawCookies[0], "Domain=") {
		t.Errorf("Set-Cookie should not contain Domain attribute\nraw: %s", rawCookies[0])
	}
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

func TestSetFallbackProxy_RewriteSetCookieDomainWithDot(t *testing.T) {
	fb := newTestFallback(t)
	var upstreamHost string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
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

// HTML 里指向上游 host 的绝对 URL 要改写成客户端 origin，否则子资源越过回退代理直连上游。
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
	if !bytes.Contains([]byte(csp), []byte("api."+upstreamHost)) {
		t.Errorf("CSP should still contain api.%s\ncsp: %s", upstreamHost, csp)
	}
}

// CSP 里不带 scheme 的裸主机源（GitHub 的 worker-src 就是这种）同样要重写。
func TestSetFallbackProxy_RewriteCSPBareHost(t *testing.T) {
	fb := newTestFallback(t)
	var upstreamHost string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
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
	// 用空格前缀限定独立 token，避免命中 gist.<host> 的子串。
	if strings.Contains(csp, " "+upstreamHost+"/assets-cdn/worker/") {
		t.Errorf("CSP should not contain bare %q/assets-cdn/worker/\ncsp: %s", upstreamHost, csp)
	}
	if !strings.Contains(csp, "my-site.com/assets-cdn/worker/") {
		t.Errorf("CSP should contain my-site.com/assets-cdn/worker/\ncsp: %s", csp)
	}
	if !strings.Contains(csp, "my-site.com/assets/") {
		t.Errorf("CSP should contain my-site.com/assets/\ncsp: %s", csp)
	}
	if !strings.Contains(csp, "gist."+upstreamHost) {
		t.Errorf("CSP should still contain gist.%s\ncsp: %s", upstreamHost, csp)
	}
}

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
	if bytes.Contains([]byte(csp), []byte("https://"+upstreamHost)) {
		t.Errorf("CSP should not contain https://%s\ncsp: %s", upstreamHost, csp)
	}
	if bytes.Contains([]byte(csp), []byte(" "+upstreamHost+"/")) {
		t.Errorf("CSP should not contain bare %q/\ncsp: %s", upstreamHost, csp)
	}
	if !bytes.Contains([]byte(csp), []byte("my-site.com")) {
		t.Errorf("CSP should contain my-site.com\ncsp: %s", csp)
	}
	if !bytes.Contains([]byte(csp), []byte("api."+upstreamHost)) {
		t.Errorf("CSP should still contain api.%s\ncsp: %s", upstreamHost, csp)
	}
	if !bytes.Contains([]byte(csp), []byte("other.example.com")) {
		t.Errorf("CSP should still contain other.example.com\ncsp: %s", csp)
	}
}

func TestSetFallbackProxy_RewriteContentGzip(t *testing.T) {
	fb := newTestFallback(t)
	var upstreamHost string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 上游忽略 identity、照旧发 gzip 时也必须能解压重写。
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

	if bytes.Contains(rec.Body.Bytes(), []byte("my-site.com")) {
		t.Errorf("non-HTML body should not be rewritten\nbody: %s", rec.Body.String())
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte(upstreamHost)) {
		t.Errorf("non-HTML body should contain upstream host\nbody: %s", rec.Body.String())
	}
}

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
	rec := httptest.NewRecorder()
	fb.Serve(rec, req)

	if gotAE != "identity" {
		t.Errorf("upstream received Accept-Encoding %q, want %q", gotAE, "identity")
	}
}

// 重写后按客户端的 Accept-Encoding 决定是否重新压缩。
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

// 客户端没要 gzip 就不能回 gzip，否则浏览器解不开。
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

// Origin 必须改写成上游 host，否则 Rails 的 CSRF 防护会拒绝该请求。
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

// /__cdn__/<host>/<path> 的请求以路径里的 host 为目标，而不是主上游。
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

	// 实例是测试私有的，跳过自签名证书校验无需还原。
	fb.proxy.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

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

// 不在允许列表的 host 必须落回主上游，否则 /__cdn__/ 就成了开放代理。
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

	req := httptest.NewRequest(http.MethodGet, cdnPathPrefix+"evil.cdn.com/assets/foo.css", nil)
	req.Host = "my-site.com"
	rec := httptest.NewRecorder()
	fb.Serve(rec, req)

	if gotPath != cdnPathPrefix+"evil.cdn.com/assets/foo.css" {
		t.Errorf("upstream received Path %q, want %q (passed through)", gotPath, cdnPathPrefix+"evil.cdn.com/assets/foo.css")
	}
}

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
	if strings.Contains(body, "https://"+cdnHost) {
		t.Errorf("body should not contain https://%s\nbody: %s", cdnHost, body)
	}
}

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
	wantCSPHost := "my-site.com" + cdnPathPrefix + cdnHost
	if !strings.Contains(csp, "http://"+wantCSPHost) {
		t.Errorf("CSP should contain http://%s\ncsp: %s", wantCSPHost, csp)
	}
	// 原始 CDN 主机与重写形式并存，JS 动态构造的 CDN URL 才不会被 CSP 拦下。
}

// 未配置的域名留在原地，不当作 CDN。
func TestSetFallbackProxy_CDNNotConfigured(t *testing.T) {
	fb := newTestFallback(t)
	cdnHost := "cdn.example.com"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><link href="https://` + cdnHost + `/foo.css"></html>`)) //nolint:errcheck
	}))
	defer upstream.Close()

	if err := fb.setProxy(upstream.URL, false, nil); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "my-site.com"
	rec := httptest.NewRecorder()
	fb.Serve(rec, req)

	body := rec.Body.String()
	if !strings.Contains(body, "https://"+cdnHost+"/foo.css") {
		t.Errorf("body should contain unchanged CDN URL\nbody: %s", body)
	}
}

// 子域的 /__cdn__/ 请求以子域主机为目标，不折叠到父域。
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

	// 子域在测试环境解析不了，用自定义 Transport 只捕获目标主机。
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

// x-es 头必须在转发前剥掉，否则代理协议痕迹会漏给回退站点。
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

// roundTripFunc 只捕获请求，不建立真实连接。
type roundTripFunc struct {
	fn func(*http.Request) (*http.Response, error)
}

func (rt *roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return rt.fn(req)
}

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

	if err := fb.setProxy(upstream.URL, false, []string{cdnParent}); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "my-site.com"
	rec := httptest.NewRecorder()
	fb.Serve(rec, req)

	body := rec.Body.String()
	wantSub := "http://my-site.com" + cdnPathPrefix + cdnSub + "/assets/foo.css"
	if !strings.Contains(body, wantSub) {
		t.Errorf("body should contain %q\nbody: %s", wantSub, body)
	}
	wantParent := "http://my-site.com" + cdnPathPrefix + cdnParent + "/assets/bar.css"
	if !strings.Contains(body, wantParent) {
		t.Errorf("body should contain %q\nbody: %s", wantParent, body)
	}
	if strings.Contains(body, "https://"+cdnSub) {
		t.Errorf("body should not contain https://%s\nbody: %s", cdnSub, body)
	}
	if strings.Contains(body, "https://"+cdnParent) {
		t.Errorf("body should not contain https://%s\nbody: %s", cdnParent, body)
	}
}

// 只按字符串后缀判断子域，会把 notgithubassets.com 误判成 githubassets.com 的子域。
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
	if !strings.Contains(body, "https://"+fakeHost+"/foo.css") {
		t.Errorf("body should contain unchanged %q URL\nbody: %s", fakeHost, body)
	}
	if strings.Contains(body, cdnPathPrefix+fakeHost) {
		t.Errorf("body should not contain /__cdn__/%s\nbody: %s", fakeHost, body)
	}
}

func TestSetFallbackProxy_CDNCSPSubdomainRewrite(t *testing.T) {
	fb := newTestFallback(t)
	cdnParent := "githubassets.com"
	cdnSub := "github.githubassets.com"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; style-src 'self' https://"+cdnSub+" "+cdnSub+"/assets/ "+
				cdnSub+" https://"+cdnParent+" "+cdnParent+"/assets/")
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
	wantSubScheme := "http://my-site.com" + cdnPathPrefix + cdnSub
	if !strings.Contains(csp, wantSubScheme) {
		t.Errorf("CSP should contain %q\ncsp: %s", wantSubScheme, csp)
	}
	wantSubBare := "my-site.com" + cdnPathPrefix + cdnSub
	if !strings.Contains(csp, wantSubBare+"/assets/") {
		t.Errorf("CSP should contain %q/assets/\ncsp: %s", wantSubBare, csp)
	}
	wantParentScheme := "http://my-site.com" + cdnPathPrefix + cdnParent
	if !strings.Contains(csp, wantParentScheme) {
		t.Errorf("CSP should contain %q\ncsp: %s", wantParentScheme, csp)
	}
}

// 响应体读不出来（不支持的 br 编码）时 CSP 仍必须重写，否则 /__cdn__/ 路径被 CSP 拦掉。
func TestSetFallbackProxy_CSPRewrittenEvenWhenBodyUnreadable(t *testing.T) {
	fb := newTestFallback(t)
	cdnParent := "githubassets.com"
	cdnSub := "github.githubassets.com"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		// 返回无法解压的 br，让响应体重写走跳过分支。
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
	if !strings.Contains(csp, "my-site.com"+cdnPathPrefix+cdnSub) {
		t.Errorf("CSP should contain my-site.com%s%s\ncsp: %s", cdnPathPrefix, cdnSub, csp)
	}
}

// 裸主机的 CSP 源重写后必须带末尾 /，否则只精确匹配该路径、子资源被拦。
func TestSetFallbackProxy_CDNCSPTrailingSlash(t *testing.T) {
	fb := newTestFallback(t)
	cdnParent := "githubassets.com"
	cdnSub := "github.githubassets.com"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
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
	wantBare := "my-site.com" + cdnPathPrefix + cdnSub + "/"
	if !strings.Contains(csp, wantBare) {
		t.Errorf("CSP should contain %q (with trailing /)\ncsp: %s", wantBare, csp)
	}
	wantScheme := "http://my-site.com" + cdnPathPrefix + cdnSub + "/"
	if !strings.Contains(csp, wantScheme) {
		t.Errorf("CSP should contain %q (with trailing /)\ncsp: %s", wantScheme, csp)
	}
}

// 只扫 HTML：JS 的 URL 是动态拼的，扫不可靠还白费 CPU。
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
	if !strings.Contains(body, "https://"+cdnHost) {
		t.Errorf("JS body should preserve original URL (not rewritten)\nbody: %s", body)
	}
}

// 指向 CDN 域名的 3xx 要改写成 /__cdn__/，浏览器才能通过回退代理跟随。
func TestSetFallbackProxy_CDNLocationRewrite(t *testing.T) {
	fb := newTestFallback(t)
	cdnHost := "raw.githubusercontent.com"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

func TestSetFallbackProxy_CDNLocationNotRewrittenWhenNotConfigured(t *testing.T) {
	fb := newTestFallback(t)
	cdnHost := "raw.githubusercontent.com"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "https://"+cdnHost+"/some/path")
		w.WriteHeader(http.StatusFound)
	}))
	defer upstream.Close()

	if err := fb.setProxy(upstream.URL, false, []string{"githubassets.com"}); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "my-site.com"
	rec := httptest.NewRecorder()
	fb.Serve(rec, req)

	want := "https://" + cdnHost + "/some/path"
	if got := rec.Header().Get("Location"); got != want {
		t.Errorf("Location = %q, want %q (unchanged)", got, want)
	}
}
