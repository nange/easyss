package handler

import (
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestServeFallback_DifferentPathsDifferentContent(t *testing.T) {
	paths := []string{"/", "/about", "/contact", "/services", "/blog"}
	seen := make(map[string]string)

	for _, path := range paths {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		ServeFallback(rec, req)

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
	req1 := httptest.NewRequest(http.MethodGet, "/about", nil)
	rec1 := httptest.NewRecorder()
	ServeFallback(rec1, req1)

	req2 := httptest.NewRequest(http.MethodGet, "/about", nil)
	rec2 := httptest.NewRecorder()
	ServeFallback(rec2, req2)

	if rec1.Body.String() != rec2.Body.String() {
		t.Error("same path returned different content")
	}
}

func TestServeFallback_CustomHTML(t *testing.T) {
	custom := []byte("<html><body>custom</body></html>")
	SetFallbackHTML(custom)
	t.Cleanup(func() { customFallback = nil })

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	ServeFallback(rec, req)

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

func TestHashIndex_SameInputSameOutput(t *testing.T) {
	a := hashIndex("hello", 5)
	b := hashIndex("hello", 5)
	if a != b {
		t.Errorf("hashIndex not deterministic: %d vs %d", a, b)
	}
	if a < 0 || a >= 5 {
		t.Errorf("hashIndex out of range: %d", a)
	}
}

// ---------------------------------------------------------------------------
// Directory-based fallback tests
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
	dir := makeFallbackDir(t, map[string]string{
		"index.html":   "<h1>Home</h1>",
		"about.html":   "<h1>About</h1>",
		"contact.html": "<h1>Contact</h1>",
	})
	if err := SetFallbackDir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fallbackPages = nil; fallback404 = nil })

	for _, tt := range []struct{ path, want string }{
		{"/", "<h1>Home</h1>"},
		{"/about", "<h1>About</h1>"},
		{"/contact", "<h1>Contact</h1>"},
		{"/about/", "<h1>About</h1>"},
	} {
		req := httptest.NewRequest(http.MethodGet, tt.path, nil)
		rec := httptest.NewRecorder()
		ServeFallback(rec, req)
		if rec.Body.String() != tt.want {
			t.Errorf("path %q: got %q, want %q", tt.path, rec.Body.String(), tt.want)
		}
	}
}

func TestSetFallbackDir_IndexMapping(t *testing.T) {
	dir := makeFallbackDir(t, map[string]string{
		"index.html": "<h1>Root</h1>",
	})
	if err := SetFallbackDir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fallbackPages = nil; fallback404 = nil })

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	ServeFallback(rec, req)
	if rec.Body.String() != "<h1>Root</h1>" {
		t.Errorf("got %q, want %q", rec.Body.String(), "<h1>Root</h1>")
	}
}

func TestSetFallbackDir_404Fallback(t *testing.T) {
	dir := makeFallbackDir(t, map[string]string{
		"index.html": "<h1>Home</h1>",
		"404.html":   "<h1>Not Found</h1>",
	})
	if err := SetFallbackDir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fallbackPages = nil; fallback404 = nil })

	req := httptest.NewRequest(http.MethodGet, "/nonexistent", nil)
	rec := httptest.NewRecorder()
	ServeFallback(rec, req)
	if rec.Body.String() != "<h1>Not Found</h1>" {
		t.Errorf("got %q, want %q", rec.Body.String(), "<h1>Not Found</h1>")
	}
}

func TestSetFallbackDir_No404FallbackToIndex(t *testing.T) {
	dir := makeFallbackDir(t, map[string]string{
		"index.html": "<h1>Home</h1>",
	})
	if err := SetFallbackDir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fallbackPages = nil; fallback404 = nil })

	req := httptest.NewRequest(http.MethodGet, "/nonexistent", nil)
	rec := httptest.NewRecorder()
	ServeFallback(rec, req)
	if rec.Body.String() != "<h1>Home</h1>" {
		t.Errorf("got %q, want %q", rec.Body.String(), "<h1>Home</h1>")
	}
}

func TestSetFallbackDir_NestedSubdirs(t *testing.T) {
	dir := makeFallbackDir(t, map[string]string{
		"index.html":      "<h1>Home</h1>",
		"blog/post1.html": "<h1>Post 1</h1>",
		"blog/post2.html": "<h1>Post 2</h1>",
	})
	if err := SetFallbackDir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fallbackPages = nil; fallback404 = nil })

	for _, tt := range []struct{ path, want string }{
		{"/", "<h1>Home</h1>"},
		{"/blog/post1", "<h1>Post 1</h1>"},
		{"/blog/post2", "<h1>Post 2</h1>"},
	} {
		req := httptest.NewRequest(http.MethodGet, tt.path, nil)
		rec := httptest.NewRecorder()
		ServeFallback(rec, req)
		if rec.Body.String() != tt.want {
			t.Errorf("path %q: got %q, want %q", tt.path, rec.Body.String(), tt.want)
		}
	}
}

func TestSetFallbackDir_ImplicitIndex(t *testing.T) {
	dir := makeFallbackDir(t, map[string]string{
		"index.html":      "<h1>Home</h1>",
		"blog/index.html": "<h1>Blog Home</h1>",
		"blog/post1.html": "<h1>Post 1</h1>",
	})
	if err := SetFallbackDir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fallbackPages = nil; fallback404 = nil })

	req := httptest.NewRequest(http.MethodGet, "/blog", nil)
	rec := httptest.NewRecorder()
	ServeFallback(rec, req)
	if rec.Body.String() != "<h1>Blog Home</h1>" {
		t.Errorf("got %q, want %q", rec.Body.String(), "<h1>Blog Home</h1>")
	}

	// /blog/ should also work
	req2 := httptest.NewRequest(http.MethodGet, "/blog/", nil)
	rec2 := httptest.NewRecorder()
	ServeFallback(rec2, req2)
	if rec2.Body.String() != "<h1>Blog Home</h1>" {
		t.Errorf("got %q, want %q", rec2.Body.String(), "<h1>Blog Home</h1>")
	}
}

func TestSetFallbackDir_IgnoresNonHTML(t *testing.T) {
	dir := makeFallbackDir(t, map[string]string{
		"index.html": "<h1>Home</h1>",
		"style.css":  "body { color: red; }",
		"readme.txt": "hello",
	})
	if err := SetFallbackDir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fallbackPages = nil; fallback404 = nil })

	// /style should not match style.css (not .html)
	req := httptest.NewRequest(http.MethodGet, "/style", nil)
	rec := httptest.NewRecorder()
	ServeFallback(rec, req)
	// Should fall back to index
	if rec.Body.String() != "<h1>Home</h1>" {
		t.Errorf("got %q, want index fallback %q", rec.Body.String(), "<h1>Home</h1>")
	}
}

func TestSetFallbackDir_EmptyDir(t *testing.T) {
	dir := makeFallbackDir(t, map[string]string{})
	if err := SetFallbackDir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fallbackPages = nil; fallback404 = nil })

	// Empty dir falls through to auto-generated (or custom fallback if set).
	// We just verify it doesn't panic.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	ServeFallback(rec, req)
	if rec.Body.Len() == 0 {
		t.Error("expected non-empty body from auto-generated fallback")
	}
}

func TestServeFallback_DirPriorityOverCustomHTML(t *testing.T) {
	dir := makeFallbackDir(t, map[string]string{
		"index.html": "<h1>Dir Home</h1>",
	})
	if err := SetFallbackDir(dir); err != nil {
		t.Fatal(err)
	}
	SetFallbackHTML([]byte("<h1>Custom</h1>"))
	t.Cleanup(func() { fallbackPages = nil; fallback404 = nil; customFallback = nil })

	// Directory mode takes priority over single-file custom HTML.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	ServeFallback(rec, req)
	if rec.Body.String() != "<h1>Dir Home</h1>" {
		t.Errorf("got %q, want dir mode %q", rec.Body.String(), "<h1>Dir Home</h1>")
	}
}

// ---------------------------------------------------------------------------
// Reverse proxy fallback tests
// ---------------------------------------------------------------------------

func TestSetFallbackProxy_EmptyURL(t *testing.T) {
	// Setting empty URL should disable the proxy (no error).
	if err := SetFallbackProxy("", false, nil); err != nil {
		t.Fatalf("unexpected error for empty URL: %v", err)
	}
	if fallbackProxy != nil {
		t.Error("expected fallbackProxy to be nil after empty URL")
	}
}

func TestSetFallbackProxy_InvalidURL(t *testing.T) {
	if err := SetFallbackProxy("://invalid", false, nil); err == nil {
		t.Error("expected error for invalid URL")
	}
}

func TestServeFallback_ProxyForwardsRequest(t *testing.T) {
	// Start a test upstream server that returns a known response.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Upstream", "true")
		w.Write([]byte("from-upstream:" + r.URL.Path))
	}))
	defer upstream.Close()

	if err := SetFallbackProxy(upstream.URL, false, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fallbackProxy = nil })

	req := httptest.NewRequest(http.MethodGet, "/some/path", nil)
	rec := httptest.NewRecorder()
	ServeFallback(rec, req)

	if rec.Body.String() != "from-upstream:/some/path" {
		t.Errorf("got %q, want %q", rec.Body.String(), "from-upstream:/some/path")
	}
	if rec.Header().Get("X-Upstream") != "true" {
		t.Error("expected X-Upstream header from upstream server")
	}
}

func TestServeFallback_ProxyHighestPriority(t *testing.T) {
	// Start a test upstream server.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("proxy-response"))
	}))
	defer upstream.Close()

	if err := SetFallbackProxy(upstream.URL, false, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fallbackProxy = nil })

	// Also set directory and custom HTML fallback to verify proxy wins.
	dir := makeFallbackDir(t, map[string]string{
		"index.html": "<h1>Dir Home</h1>",
	})
	if err := SetFallbackDir(dir); err != nil {
		t.Fatal(err)
	}
	SetFallbackHTML([]byte("<h1>Custom</h1>"))
	t.Cleanup(func() {
		fallbackPages = nil
		fallback404 = nil
		customFallback = nil
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	ServeFallback(rec, req)

	// Proxy should win over both directory and custom HTML.
	if rec.Body.String() != "proxy-response" {
		t.Errorf("got %q, want %q", rec.Body.String(), "proxy-response")
	}
}

// ---------------------------------------------------------------------------
// SetFallbackTarget auto-detection tests
// ---------------------------------------------------------------------------

func TestSetFallbackTarget_Empty(t *testing.T) {
	// Set some state first, then reset with empty.
	customFallback = []byte("test")
	fallbackPages = map[string][]byte{"/": []byte("test")}
	fallbackProxy = &httputil.ReverseProxy{}

	if err := SetFallbackTarget("", false, nil); err != nil {
		t.Fatal(err)
	}

	if customFallback != nil {
		t.Error("customFallback should be nil after reset")
	}
	if fallbackPages != nil {
		t.Error("fallbackPages should be nil after reset")
	}
	if fallbackProxy != nil {
		t.Error("fallbackProxy should be nil after reset")
	}
	if fallback404 != nil {
		t.Error("fallback404 should be nil after reset")
	}
}

func TestSetFallbackTarget_HTTPURL(t *testing.T) {
	t.Cleanup(func() { fallbackProxy = nil })

	if err := SetFallbackTarget("http://127.0.0.1:8080", false, nil); err != nil {
		t.Fatal(err)
	}
	if fallbackProxy == nil {
		t.Error("expected fallbackProxy to be set for HTTP URL")
	}
}

func TestSetFallbackTarget_HTTPSURL(t *testing.T) {
	t.Cleanup(func() { fallbackProxy = nil })

	if err := SetFallbackTarget("https://example.com", false, nil); err != nil {
		t.Fatal(err)
	}
	if fallbackProxy == nil {
		t.Error("expected fallbackProxy to be set for HTTPS URL")
	}
}

func TestSetFallbackTarget_Directory(t *testing.T) {
	dir := makeFallbackDir(t, map[string]string{
		"index.html": "<h1>Home</h1>",
	})
	t.Cleanup(func() { fallbackPages = nil; fallback404 = nil })

	if err := SetFallbackTarget(dir, false, nil); err != nil {
		t.Fatal(err)
	}
	if len(fallbackPages) == 0 {
		t.Error("expected fallbackPages to be populated for directory")
	}
}

func TestSetFallbackTarget_File(t *testing.T) {
	dir := makeFallbackDir(t, map[string]string{
		"custom.html": "<h1>Custom</h1>",
	})
	filePath := filepath.Join(dir, "custom.html")
	t.Cleanup(func() { customFallback = nil })

	if err := SetFallbackTarget(filePath, false, nil); err != nil {
		t.Fatal(err)
	}
	if string(customFallback) != "<h1>Custom</h1>" {
		t.Errorf("got %q, want %q", string(customFallback), "<h1>Custom</h1>")
	}
}

func TestSetFallbackTarget_InvalidPath(t *testing.T) {
	if err := SetFallbackTarget("/nonexistent/path", false, nil); err == nil {
		t.Error("expected error for nonexistent path")
	}
}

func TestSetFallbackTarget_ProxyEndToEnd(t *testing.T) {
	// Full integration: SetFallbackTarget with HTTP URL then serve a request.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("upstream:" + r.URL.Path))
	}))
	defer upstream.Close()

	if err := SetFallbackTarget(upstream.URL, false, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fallbackProxy = nil })

	req := httptest.NewRequest(http.MethodGet, "/hello", nil)
	rec := httptest.NewRecorder()
	ServeFallback(rec, req)

	if rec.Body.String() != "upstream:/hello" {
		t.Errorf("got %q, want %q", rec.Body.String(), "upstream:/hello")
	}
}

// ---------------------------------------------------------------------------
// SetFallbackProxy Host header & Location rewrite tests
// ---------------------------------------------------------------------------

// TestSetFallbackProxy_HostHeader verifies that the request forwarded to the
// upstream carries the upstream's Host (not the client-facing host). This is
// the core fix: without it, upstreams like GitHub return a 301 redirect to
// their canonical host, causing the browser address bar to jump.
func TestSetFallbackProxy_HostHeader(t *testing.T) {
	var gotHost string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Host
		w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	if err := SetFallbackProxy(upstream.URL, false, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fallbackProxy = nil })

	// Client-facing request uses a different host.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "my-site.com"
	rec := httptest.NewRecorder()
	ServeFallback(rec, req)

	want := upstream.Listener.Addr().String()
	if gotHost != want {
		t.Errorf("upstream received Host %q, want %q", gotHost, want)
	}
}

// TestSetFallbackProxy_RewriteLocation verifies that a 3xx Location header
// pointing at the upstream host is rewritten back to the client-facing host.
func TestSetFallbackProxy_RewriteLocation(t *testing.T) {
	var upstreamHost string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate an upstream that redirects to its own canonical URL.
		w.Header().Set("Location", "http://"+upstreamHost+"/some/path")
		w.WriteHeader(http.StatusMovedPermanently)
	}))
	defer upstream.Close()
	upstreamHost = upstream.Listener.Addr().String()

	if err := SetFallbackProxy(upstream.URL, false, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fallbackProxy = nil })

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "my-site.com"
	rec := httptest.NewRecorder()
	ServeFallback(rec, req)

	// httptest.NewRequest has TLS == nil, so the client-facing scheme is "http".
	if got := rec.Header().Get("Location"); got != "http://my-site.com/some/path" {
		t.Errorf("Location = %q, want %q", got, "http://my-site.com/some/path")
	}
}

// TestSetFallbackProxy_RelativeLocationUnchanged verifies that relative-path
// Location headers (e.g. "/login") are passed through unchanged.
func TestSetFallbackProxy_RelativeLocationUnchanged(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "/login")
		w.WriteHeader(http.StatusFound)
	}))
	defer upstream.Close()

	if err := SetFallbackProxy(upstream.URL, false, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fallbackProxy = nil })

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "my-site.com"
	rec := httptest.NewRecorder()
	ServeFallback(rec, req)

	if got := rec.Header().Get("Location"); got != "/login" {
		t.Errorf("Location = %q, want %q", got, "/login")
	}
}

// TestSetFallbackProxy_OtherHostLocationUnchanged verifies that Location
// headers pointing at a host other than the upstream are passed through.
func TestSetFallbackProxy_OtherHostLocationUnchanged(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "https://other.example.com/x")
		w.WriteHeader(http.StatusFound)
	}))
	defer upstream.Close()

	if err := SetFallbackProxy(upstream.URL, false, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fallbackProxy = nil })

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "my-site.com"
	rec := httptest.NewRecorder()
	ServeFallback(rec, req)

	if got := rec.Header().Get("Location"); got != "https://other.example.com/x" {
		t.Errorf("Location = %q, want %q", got, "https://other.example.com/x")
	}
}

// TestSetFallbackProxy_PreserveHost verifies that when preserveHost is true,
// the client-facing Host header is forwarded to the upstream unchanged. This
// is needed for local nginx setups that use server_name-based virtual host
// routing.
func TestSetFallbackProxy_PreserveHost(t *testing.T) {
	var gotHost string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Host
		w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	if err := SetFallbackProxy(upstream.URL, true, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fallbackProxy = nil })

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "my-site.com"
	rec := httptest.NewRecorder()
	ServeFallback(rec, req)

	if gotHost != "my-site.com" {
		t.Errorf("upstream received Host %q, want %q (preserveHost=true)", gotHost, "my-site.com")
	}
}

// TestSetFallbackProxy_PreserveHostLocationRewrite verifies that Location
// rewriting still works when preserveHost is true: if the upstream (which
// received the client-facing Host) redirects to the upstream's own address
// (e.g. via $host in nginx config), the Location is rewritten back to the
// client-facing host.
func TestSetFallbackProxy_PreserveHostLocationRewrite(t *testing.T) {
	var upstreamHost string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Upstream redirects to its own listen address (e.g. an nginx
		// config using $host without a proper server_name match).
		w.Header().Set("Location", "http://"+upstreamHost+"/login")
		w.WriteHeader(http.StatusFound)
	}))
	defer upstream.Close()
	upstreamHost = upstream.Listener.Addr().String()

	if err := SetFallbackProxy(upstream.URL, true, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fallbackProxy = nil })

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "my-site.com"
	rec := httptest.NewRecorder()
	ServeFallback(rec, req)

	if got := rec.Header().Get("Location"); got != "http://my-site.com/login" {
		t.Errorf("Location = %q, want %q", got, "http://my-site.com/login")
	}
}

// ---------------------------------------------------------------------------
// Set-Cookie header rewriting tests
// ---------------------------------------------------------------------------

// TestSetFallbackProxy_RewriteSetCookieDomain verifies that the Domain
// attribute in Set-Cookie headers pointing at the upstream host is removed so
// the browser accepts the cookie for the proxy's host.
func TestSetFallbackProxy_RewriteSetCookieDomain(t *testing.T) {
	var upstreamHost string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		// Use a raw Set-Cookie header (not http.SetCookie) to avoid the
		// standard library dropping the Domain attribute when it contains
		// a port number.
		w.Header().Add("Set-Cookie",
			"_gh_sess=abc123; Domain="+upstreamHost+"; Path=/; HttpOnly; Secure")
		w.Write([]byte("<html></html>"))
	}))
	defer upstream.Close()
	upstreamHost = upstream.Listener.Addr().String()

	if err := SetFallbackProxy(upstream.URL, false, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fallbackProxy = nil })

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "my-site.com"
	rec := httptest.NewRecorder()
	ServeFallback(rec, req)

	// Parse the raw Set-Cookie header to verify Domain was removed.
	rawCookies := rec.Result().Header["Set-Cookie"]
	if len(rawCookies) != 1 {
		t.Fatalf("expected 1 Set-Cookie header, got %d", len(rawCookies))
	}
	if strings.Contains(rawCookies[0], "Domain=") {
		t.Errorf("Set-Cookie should not contain Domain attribute\nraw: %s", rawCookies[0])
	}
	// Verify the cookie name/value and other attributes are preserved.
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

// TestSetFallbackProxy_RewriteSetCookieDomainWithDot verifies that a Domain
// attribute with a leading dot (e.g. ".github.com") is also removed.
func TestSetFallbackProxy_RewriteSetCookieDomainWithDot(t *testing.T) {
	var upstreamHost string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		// Manually set a raw Set-Cookie with leading-dot domain.
		w.Header().Add("Set-Cookie", "test=val; Domain=."+upstreamHost+"; Path=/; Secure")
		w.Write([]byte("<html></html>"))
	}))
	defer upstream.Close()
	upstreamHost = upstream.Listener.Addr().String()

	if err := SetFallbackProxy(upstream.URL, false, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fallbackProxy = nil })

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "my-site.com"
	rec := httptest.NewRecorder()
	ServeFallback(rec, req)

	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}
	if cookies[0].Domain != "" {
		t.Errorf("cookie Domain = %q, want empty (removed)", cookies[0].Domain)
	}
}

// TestSetFallbackProxy_SetCookieOtherDomainUnchanged verifies that cookies
// with a Domain pointing at a host other than the upstream are left untouched.
func TestSetFallbackProxy_SetCookieOtherDomainUnchanged(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Add("Set-Cookie", "test=val; Domain=other.example.com; Path=/")
		w.Write([]byte("<html></html>"))
	}))
	defer upstream.Close()

	if err := SetFallbackProxy(upstream.URL, false, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fallbackProxy = nil })

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "my-site.com"
	rec := httptest.NewRecorder()
	ServeFallback(rec, req)

	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}
	if cookies[0].Domain != "other.example.com" {
		t.Errorf("cookie Domain = %q, want %q (unchanged)", cookies[0].Domain, "other.example.com")
	}
}

// TestSetFallbackProxy_SetCookieNoDomainUnchanged verifies that cookies
// without a Domain attribute are left untouched.
func TestSetFallbackProxy_SetCookieNoDomainUnchanged(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		http.SetCookie(w, &http.Cookie{
			Name:  "test",
			Value: "val",
			Path:  "/",
		})
		w.Write([]byte("<html></html>"))
	}))
	defer upstream.Close()

	if err := SetFallbackProxy(upstream.URL, false, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fallbackProxy = nil })

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "my-site.com"
	rec := httptest.NewRecorder()
	ServeFallback(rec, req)

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
// SetFallbackProxy content rewriting tests (always enabled in URL mode)
// ---------------------------------------------------------------------------

// TestSetFallbackProxy_RewriteContent verifies that absolute URLs in an HTML
// response body pointing at the upstream host are rewritten to the
// client-facing origin.
func TestSetFallbackProxy_RewriteContent(t *testing.T) {
	var upstreamHost string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(`<html><a href="https://` + upstreamHost + `/repo">link</a>` +
			`<turbo-frame src="https://` + upstreamHost + `/repo/releases/expanded_assets/v1">` +
			`</turbo-frame></html>`))
	}))
	defer upstream.Close()
	upstreamHost = upstream.Listener.Addr().String()

	if err := SetFallbackProxy(upstream.URL, false, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fallbackProxy = nil })

	req := httptest.NewRequest(http.MethodGet, "/repo/releases", nil)
	req.Host = "my-site.com"
	rec := httptest.NewRecorder()
	ServeFallback(rec, req)

	// httptest.NewRequest has TLS == nil, so origScheme defaults to "http".
	body := rec.Body.String()
	want := "http://my-site.com/repo"
	if !bytes.Contains([]byte(body), []byte(want)) {
		t.Errorf("body does not contain %q\nbody: %s", want, body)
	}
	if bytes.Contains([]byte(body), []byte(upstreamHost)) {
		t.Errorf("body should not contain upstream host %q\nbody: %s", upstreamHost, body)
	}
}

// TestSetFallbackProxy_RewriteContentCSP verifies that the
// Content-Security-Policy header is rewritten to replace upstream URLs with
// the client-facing origin.
func TestSetFallbackProxy_RewriteContentCSP(t *testing.T) {
	var upstreamHost string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; connect-src 'self' https://"+upstreamHost+" api."+upstreamHost)
		w.Write([]byte("<html></html>"))
	}))
	defer upstream.Close()
	upstreamHost = upstream.Listener.Addr().String()

	if err := SetFallbackProxy(upstream.URL, false, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fallbackProxy = nil })

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "my-site.com"
	rec := httptest.NewRecorder()
	ServeFallback(rec, req)

	csp := rec.Header().Get("Content-Security-Policy")
	if bytes.Contains([]byte(csp), []byte("https://"+upstreamHost)) {
		t.Errorf("CSP should not contain https://%s\ncsp: %s", upstreamHost, csp)
	}
	// httptest.NewRequest has TLS == nil → origScheme = "http".
	if !bytes.Contains([]byte(csp), []byte("http://my-site.com")) {
		t.Errorf("CSP should contain http://my-site.com\ncsp: %s", csp)
	}
	// Subdomain references should be preserved (not replaced).
	if !bytes.Contains([]byte(csp), []byte("api."+upstreamHost)) {
		t.Errorf("CSP should still contain api.%s\ncsp: %s", upstreamHost, csp)
	}
}

// TestSetFallbackProxy_RewriteCSPBareHost verifies that bare-host source
// expressions in CSP (without a scheme prefix, e.g.
// "github.com/assets-cdn/worker/") are rewritten to the client-facing host.
// This is needed for GitHub's worker-src directive which uses scheme-less
// paths.
func TestSetFallbackProxy_RewriteCSPBareHost(t *testing.T) {
	var upstreamHost string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		// Simulate GitHub-style CSP with bare-host paths in worker-src.
		w.Header().Set("Content-Security-Policy",
			"worker-src "+upstreamHost+"/assets-cdn/worker/ "+upstreamHost+"/assets/ gist."+upstreamHost+"/assets-cdn/worker/")
		w.Write([]byte("<html></html>"))
	}))
	defer upstream.Close()
	upstreamHost = upstream.Listener.Addr().String()

	if err := SetFallbackProxy(upstream.URL, false, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fallbackProxy = nil })

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "my-site.com"
	rec := httptest.NewRecorder()
	ServeFallback(rec, req)

	csp := rec.Header().Get("Content-Security-Policy")
	// Bare upstream host should be replaced with client-facing host.
	// Check that no space-prefixed upstream host path remains (the space
	// ensures we match a standalone token, not a substring of "gist.").
	if strings.Contains(csp, " "+upstreamHost+"/assets-cdn/worker/") {
		t.Errorf("CSP should not contain bare %q/assets-cdn/worker/\ncsp: %s", upstreamHost, csp)
	}
	if !strings.Contains(csp, "my-site.com/assets-cdn/worker/") {
		t.Errorf("CSP should contain my-site.com/assets-cdn/worker/\ncsp: %s", csp)
	}
	if !strings.Contains(csp, "my-site.com/assets/") {
		t.Errorf("CSP should contain my-site.com/assets/\ncsp: %s", csp)
	}
	// Subdomain references should be preserved (not replaced).
	if !strings.Contains(csp, "gist."+upstreamHost) {
		t.Errorf("CSP should still contain gist.%s\ncsp: %s", upstreamHost, csp)
	}
}

// TestSetFallbackProxy_RewriteCSPMixed verifies that a CSP with both
// scheme-prefixed and bare-host forms of the upstream host are all rewritten
// correctly, while other hosts and subdomains are preserved.
func TestSetFallbackProxy_RewriteCSPMixed(t *testing.T) {
	var upstreamHost string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Content-Security-Policy",
			"connect-src 'self' https://"+upstreamHost+" "+upstreamHost+"/api "+
				"api."+upstreamHost+" https://other.example.com")
		w.Write([]byte("<html></html>"))
	}))
	defer upstream.Close()
	upstreamHost = upstream.Listener.Addr().String()

	if err := SetFallbackProxy(upstream.URL, false, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fallbackProxy = nil })

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "my-site.com"
	rec := httptest.NewRecorder()
	ServeFallback(rec, req)

	csp := rec.Header().Get("Content-Security-Policy")
	// No upstream host should remain (except subdomain api.).
	if bytes.Contains([]byte(csp), []byte("https://"+upstreamHost)) {
		t.Errorf("CSP should not contain https://%s\ncsp: %s", upstreamHost, csp)
	}
	if bytes.Contains([]byte(csp), []byte(" "+upstreamHost+"/")) {
		t.Errorf("CSP should not contain bare %q/\ncsp: %s", upstreamHost, csp)
	}
	// Client-facing host should be present.
	if !bytes.Contains([]byte(csp), []byte("my-site.com")) {
		t.Errorf("CSP should contain my-site.com\ncsp: %s", csp)
	}
	// Subdomain and other host should be preserved.
	if !bytes.Contains([]byte(csp), []byte("api."+upstreamHost)) {
		t.Errorf("CSP should still contain api.%s\ncsp: %s", upstreamHost, csp)
	}
	if !bytes.Contains([]byte(csp), []byte("other.example.com")) {
		t.Errorf("CSP should still contain other.example.com\ncsp: %s", csp)
	}
}

// TestSetFallbackProxy_RewriteContentGzip verifies that gzipped HTML
// responses are decompressed and rewritten correctly.
func TestSetFallbackProxy_RewriteContentGzip(t *testing.T) {
	var upstreamHost string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate an upstream that ignores Accept-Encoding: identity
		// and sends gzip anyway.
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Content-Encoding", "gzip")
		gw := gzip.NewWriter(w)
		gw.Write([]byte(`<html><a href="https://` + upstreamHost + `/test">link</a></html>`))
		gw.Close()
	}))
	defer upstream.Close()
	upstreamHost = upstream.Listener.Addr().String()

	if err := SetFallbackProxy(upstream.URL, false, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fallbackProxy = nil })

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "my-site.com"
	rec := httptest.NewRecorder()
	ServeFallback(rec, req)

	// Content-Encoding should be removed (we send uncompressed after rewriting).
	if ce := rec.Header().Get("Content-Encoding"); ce != "" {
		t.Errorf("Content-Encoding = %q, want empty", ce)
	}
	body := rec.Body.String()
	// httptest.NewRequest has TLS == nil → origScheme = "http".
	if !bytes.Contains([]byte(body), []byte("http://my-site.com/test")) {
		t.Errorf("body should contain rewritten URL\nbody: %s", body)
	}
	if bytes.Contains([]byte(body), []byte(upstreamHost)) {
		t.Errorf("body should not contain upstream host %q\nbody: %s", upstreamHost, body)
	}
}

// TestSetFallbackProxy_RewriteContentNonHTML verifies that non-HTML responses
// are passed through unchanged (only HTML is rewritten).
func TestSetFallbackProxy_RewriteContentNonHTML(t *testing.T) {
	var upstreamHost string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"url":"https://` + upstreamHost + `/api"}`))
	}))
	defer upstream.Close()
	upstreamHost = upstream.Listener.Addr().String()

	if err := SetFallbackProxy(upstream.URL, false, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fallbackProxy = nil })

	req := httptest.NewRequest(http.MethodGet, "/api", nil)
	req.Host = "my-site.com"
	rec := httptest.NewRecorder()
	ServeFallback(rec, req)

	// JSON should not be rewritten.
	if bytes.Contains([]byte(rec.Body.String()), []byte("my-site.com")) {
		t.Errorf("non-HTML body should not be rewritten\nbody: %s", rec.Body.String())
	}
	if !bytes.Contains([]byte(rec.Body.String()), []byte(upstreamHost)) {
		t.Errorf("non-HTML body should contain upstream host\nbody: %s", rec.Body.String())
	}
}

// TestSetFallbackProxy_RewriteContentAcceptEncoding_ClientGzip verifies that
// when the client accepts gzip, the upstream receives "identity, gzip".
func TestSetFallbackProxy_RewriteContentAcceptEncoding_ClientGzip(t *testing.T) {
	var gotAE string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAE = r.Header.Get("Accept-Encoding")
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html></html>"))
	}))
	defer upstream.Close()

	if err := SetFallbackProxy(upstream.URL, false, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fallbackProxy = nil })

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "my-site.com"
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	rec := httptest.NewRecorder()
	ServeFallback(rec, req)

	if gotAE != "identity, gzip" {
		t.Errorf("upstream received Accept-Encoding %q, want %q", gotAE, "identity, gzip")
	}
}

// TestSetFallbackProxy_RewriteContentAcceptEncoding_ClientNoGzip verifies that
// when the client does not accept gzip, the upstream receives "identity" only.
func TestSetFallbackProxy_RewriteContentAcceptEncoding_ClientNoGzip(t *testing.T) {
	var gotAE string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAE = r.Header.Get("Accept-Encoding")
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html></html>"))
	}))
	defer upstream.Close()

	if err := SetFallbackProxy(upstream.URL, false, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fallbackProxy = nil })

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "my-site.com"
	// No Accept-Encoding header → client does not accept gzip.
	rec := httptest.NewRecorder()
	ServeFallback(rec, req)

	if gotAE != "identity" {
		t.Errorf("upstream received Accept-Encoding %q, want %q", gotAE, "identity")
	}
}

// TestSetFallbackProxy_RewriteContent_RecompressGzip verifies that when the
// client accepts gzip, the rewritten HTML response is re-compressed with gzip
// and the Content-Encoding header is set to "gzip".
func TestSetFallbackProxy_RewriteContent_RecompressGzip(t *testing.T) {
	var upstreamHost string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><a href="https://` + upstreamHost + `/test">link</a></html>`))
	}))
	defer upstream.Close()
	upstreamHost = upstream.Listener.Addr().String()

	if err := SetFallbackProxy(upstream.URL, false, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fallbackProxy = nil })

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "my-site.com"
	req.Header.Set("Accept-Encoding", "gzip")
	rec := httptest.NewRecorder()
	ServeFallback(rec, req)

	if ce := rec.Header().Get("Content-Encoding"); ce != "gzip" {
		t.Errorf("Content-Encoding = %q, want %q", ce, "gzip")
	}

	// Decompress the response body and verify the rewritten URL.
	gr, err := gzip.NewReader(rec.Body)
	if err != nil {
		t.Fatalf("gzip reader: %v", err)
	}
	body, _ := io.ReadAll(gr)
	gr.Close()
	if !bytes.Contains(body, []byte("http://my-site.com/test")) {
		t.Errorf("decompressed body should contain rewritten URL\nbody: %s", body)
	}
	if bytes.Contains(body, []byte(upstreamHost)) {
		t.Errorf("body should not contain upstream host %q\nbody: %s", upstreamHost, body)
	}
}

// TestSetFallbackProxy_RewriteContent_NoRecompressWhenClientNoGzip verifies
// that when the client does not accept gzip, the rewritten HTML is sent
// uncompressed even if the upstream returned gzip.
func TestSetFallbackProxy_RewriteContent_NoRecompressWhenClientNoGzip(t *testing.T) {
	var upstreamHost string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Content-Encoding", "gzip")
		gw := gzip.NewWriter(w)
		gw.Write([]byte(`<html><a href="https://` + upstreamHost + `/test">link</a></html>`))
		gw.Close()
	}))
	defer upstream.Close()
	upstreamHost = upstream.Listener.Addr().String()

	if err := SetFallbackProxy(upstream.URL, false, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fallbackProxy = nil })

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "my-site.com"
	// No Accept-Encoding → client does not accept gzip.
	rec := httptest.NewRecorder()
	ServeFallback(rec, req)

	if ce := rec.Header().Get("Content-Encoding"); ce != "" {
		t.Errorf("Content-Encoding = %q, want empty (client does not accept gzip)", ce)
	}
	body := rec.Body.String()
	if !bytes.Contains([]byte(body), []byte("http://my-site.com/test")) {
		t.Errorf("body should contain rewritten URL\nbody: %s", body)
	}
}

// TestClientAcceptsGzip verifies the clientAcceptsGzip helper function.
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
// Origin / Referer request header rewriting tests
// ---------------------------------------------------------------------------

// TestSetFallbackProxy_RewriteOrigin verifies that the Origin header on POST
// requests is rewritten from the client-facing host to the upstream host so
// that Rails CSRF protection accepts the request.
func TestSetFallbackProxy_RewriteOrigin(t *testing.T) {
	var gotOrigin string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotOrigin = r.Header.Get("Origin")
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html></html>"))
	}))
	defer upstream.Close()
	upstreamHost := upstream.Listener.Addr().String()

	if err := SetFallbackProxy(upstream.URL, false, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fallbackProxy = nil })

	req := httptest.NewRequest(http.MethodPost, "/session", nil)
	req.Host = "my-site.com"
	req.Header.Set("Origin", "http://my-site.com")
	rec := httptest.NewRecorder()
	ServeFallback(rec, req)

	want := "http://" + upstreamHost
	if gotOrigin != want {
		t.Errorf("upstream received Origin %q, want %q", gotOrigin, want)
	}
}

// TestSetFallbackProxy_RewriteReferer verifies that the Referer header is
// rewritten from the client-facing host to the upstream host, preserving the
// path.
func TestSetFallbackProxy_RewriteReferer(t *testing.T) {
	var gotReferer string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotReferer = r.Header.Get("Referer")
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html></html>"))
	}))
	defer upstream.Close()
	upstreamHost := upstream.Listener.Addr().String()

	if err := SetFallbackProxy(upstream.URL, false, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fallbackProxy = nil })

	req := httptest.NewRequest(http.MethodPost, "/session", nil)
	req.Host = "my-site.com"
	req.Header.Set("Referer", "http://my-site.com/login")
	rec := httptest.NewRecorder()
	ServeFallback(rec, req)

	want := "http://" + upstreamHost + "/login"
	if gotReferer != want {
		t.Errorf("upstream received Referer %q, want %q", gotReferer, want)
	}
}

// TestSetFallbackProxy_OtherHostOriginUnchanged verifies that Origin headers
// pointing at a host other than the client-facing host are left untouched.
func TestSetFallbackProxy_OtherHostOriginUnchanged(t *testing.T) {
	var gotOrigin string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotOrigin = r.Header.Get("Origin")
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html></html>"))
	}))
	defer upstream.Close()

	if err := SetFallbackProxy(upstream.URL, false, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fallbackProxy = nil })

	req := httptest.NewRequest(http.MethodPost, "/session", nil)
	req.Host = "my-site.com"
	req.Header.Set("Origin", "http://other.example.com")
	rec := httptest.NewRecorder()
	ServeFallback(rec, req)

	if gotOrigin != "http://other.example.com" {
		t.Errorf("upstream received Origin %q, want %q (unchanged)", gotOrigin, "http://other.example.com")
	}
}

// TestSetFallbackProxy_NoOriginNoError verifies that requests without an
// Origin or Referer header are handled without error.
func TestSetFallbackProxy_NoOriginNoError(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html></html>"))
	}))
	defer upstream.Close()

	if err := SetFallbackProxy(upstream.URL, false, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fallbackProxy = nil })

	req := httptest.NewRequest(http.MethodPost, "/session", nil)
	req.Host = "my-site.com"
	rec := httptest.NewRecorder()
	ServeFallback(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

// ---------------------------------------------------------------------------
// CDN domain proxying tests
// ---------------------------------------------------------------------------

// TestSetFallbackProxy_CDNRoute verifies that a request to
// /__cdn__/<host>/<path> is proxied to https://<host>/<path> with the correct
// Host header.
func TestSetFallbackProxy_CDNRoute(t *testing.T) {
	var gotHost, gotPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("upstream"))
	}))
	defer upstream.Close()

	cdnServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Host
		gotPath = r.URL.Path
		w.Write([]byte("cdn-content"))
	}))
	defer cdnServer.Close()
	cdnHost := cdnServer.Listener.Addr().String()

	if err := SetFallbackProxy(upstream.URL, false, []string{cdnHost}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fallbackProxy = nil; fallbackCDNHosts = nil })

	// Override the proxy's Transport to skip TLS verification for the test
	// self-signed certificate.
	originalTransport := fallbackProxy.Transport
	fallbackProxy.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	t.Cleanup(func() { fallbackProxy.Transport = originalTransport })

	// Request via /__cdn__/ prefix path.
	req := httptest.NewRequest(http.MethodGet, cdnPathPrefix+cdnHost+"/assets/foo.css", nil)
	req.Host = "my-site.com"
	rec := httptest.NewRecorder()
	ServeFallback(rec, req)

	if gotHost != cdnHost {
		t.Errorf("CDN received Host %q, want %q", gotHost, cdnHost)
	}
	if gotPath != "/assets/foo.css" {
		t.Errorf("CDN received Path %q, want %q", gotPath, "/assets/foo.css")
	}
}

// TestSetFallbackProxy_CDNRouteDisallowedHost verifies that a /__cdn__/
// request to a host NOT in the allowed list is not proxied as a CDN request
// (it falls through to the main upstream).
func TestSetFallbackProxy_CDNRouteDisallowedHost(t *testing.T) {
	var gotPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Write([]byte("upstream"))
	}))
	defer upstream.Close()

	if err := SetFallbackProxy(upstream.URL, false, []string{"allowed.cdn.com"}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fallbackProxy = nil; fallbackCDNHosts = nil })

	// Request to a disallowed CDN host.
	req := httptest.NewRequest(http.MethodGet, cdnPathPrefix+"evil.cdn.com/assets/foo.css", nil)
	req.Host = "my-site.com"
	rec := httptest.NewRecorder()
	ServeFallback(rec, req)

	// Should have been routed to the main upstream with the /__cdn__/ path
	// (since the host was not in the allowed set, routeCDN returns false and
	// the normal upstream routing applies).
	if gotPath != cdnPathPrefix+"evil.cdn.com/assets/foo.css" {
		t.Errorf("upstream received Path %q, want %q (passed through)", gotPath, cdnPathPrefix+"evil.cdn.com/assets/foo.css")
	}
}

// TestSetFallbackProxy_CDNHTMLRewrite verifies that absolute URLs pointing at
// a configured CDN domain in an HTML body are rewritten to the
// /__cdn__/<host> prefix form.
func TestSetFallbackProxy_CDNHTMLRewrite(t *testing.T) {
	var upstreamHost string
	cdnHost := "cdn.example.com"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><link rel="stylesheet" href="https://` + cdnHost + `/assets/foo.css">` +
			`<script src="https://` + cdnHost + `/assets/bar.js"></script></html>`))
	}))
	defer upstream.Close()
	upstreamHost = upstream.Listener.Addr().String()
	_ = upstreamHost

	if err := SetFallbackProxy(upstream.URL, false, []string{cdnHost}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fallbackProxy = nil; fallbackCDNHosts = nil })

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "my-site.com"
	rec := httptest.NewRecorder()
	ServeFallback(rec, req)

	body := rec.Body.String()
	wantPrefix := "http://my-site.com" + cdnPathPrefix + cdnHost
	if !strings.Contains(body, wantPrefix+"/assets/foo.css") {
		t.Errorf("body should contain %q/assets/foo.css\nbody: %s", wantPrefix, body)
	}
	if !strings.Contains(body, wantPrefix+"/assets/bar.js") {
		t.Errorf("body should contain %q/assets/bar.js\nbody: %s", wantPrefix, body)
	}
	// Original CDN URL should not appear.
	if strings.Contains(body, "https://"+cdnHost) {
		t.Errorf("body should not contain https://%s\nbody: %s", cdnHost, body)
	}
}

// TestSetFallbackProxy_CDNCSPRewrite verifies that CSP source expressions
// referencing a configured CDN domain are rewritten to the /__cdn__/ prefix
// form.
func TestSetFallbackProxy_CDNCSPRewrite(t *testing.T) {
	cdnHost := "cdn.example.com"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; style-src 'self' https://"+cdnHost+" "+cdnHost+"/assets/; script-src "+cdnHost)
		w.Write([]byte("<html></html>"))
	}))
	defer upstream.Close()

	if err := SetFallbackProxy(upstream.URL, false, []string{cdnHost}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fallbackProxy = nil; fallbackCDNHosts = nil })

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "my-site.com"
	rec := httptest.NewRecorder()
	ServeFallback(rec, req)

	csp := rec.Header().Get("Content-Security-Policy")
	// CDN host should be replaced with my-site.com/__cdn__/<cdnHost>.
	wantCSPHost := "my-site.com" + cdnPathPrefix + cdnHost
	if strings.Contains(csp, "https://"+cdnHost) {
		t.Errorf("CSP should not contain https://%s\ncsp: %s", cdnHost, csp)
	}
	if !strings.Contains(csp, "http://"+wantCSPHost) {
		t.Errorf("CSP should contain http://%s\ncsp: %s", wantCSPHost, csp)
	}
	// Bare-host form should also be replaced.
	if strings.Contains(csp, " "+cdnHost+"/") {
		t.Errorf("CSP should not contain bare %q/\ncsp: %s", cdnHost, csp)
	}
}

// TestSetFallbackProxy_CDNNotConfigured verifies that when no CDN domains are
// configured, HTML URLs pointing at external hosts are NOT rewritten (left
// as-is).
func TestSetFallbackProxy_CDNNotConfigured(t *testing.T) {
	cdnHost := "cdn.example.com"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><link href="https://` + cdnHost + `/foo.css"></html>`))
	}))
	defer upstream.Close()

	// No CDN domains configured.
	if err := SetFallbackProxy(upstream.URL, false, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fallbackProxy = nil; fallbackCDNHosts = nil })

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "my-site.com"
	rec := httptest.NewRecorder()
	ServeFallback(rec, req)

	body := rec.Body.String()
	// CDN URL should remain unchanged.
	if !strings.Contains(body, "https://"+cdnHost+"/foo.css") {
		t.Errorf("body should contain unchanged CDN URL\nbody: %s", body)
	}
}

// TestSetFallbackProxy_CDNSubdomainRoute verifies that a /__cdn__/ request to
// a subdomain of a configured CDN domain is routed correctly (the subdomain
// host is extracted and used as the upstream host).
func TestSetFallbackProxy_CDNSubdomainRoute(t *testing.T) {
	cdnParent := "githubassets.com"
	cdnSub := "github.githubassets.com"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("upstream"))
	}))
	defer upstream.Close()

	if err := SetFallbackProxy(upstream.URL, false, []string{cdnParent}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fallbackProxy = nil; fallbackCDNHosts = nil })

	// Use a custom Transport that captures the target host without actually
	// connecting (the subdomain is not DNS-resolvable in test env).
	var capturedHost string
	fallbackProxy.Transport = &roundTripFunc{
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
	ServeFallback(rec, req)

	if capturedHost != cdnSub {
		t.Errorf("upstream host = %q, want %q (subdomain)", capturedHost, cdnSub)
	}
}

// roundTripFunc is a helper Transport for testing that captures the request
// without making a real network connection.
type roundTripFunc struct {
	fn func(*http.Request) (*http.Response, error)
}

func (rt *roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return rt.fn(req)
}

// TestSetFallbackProxy_CDNSubdomainHTMLRewrite verifies that absolute URLs
// pointing at a subdomain of a configured CDN domain are rewritten to
// /__cdn__/<subdomain-host> form.
func TestSetFallbackProxy_CDNSubdomainHTMLRewrite(t *testing.T) {
	cdnParent := "githubassets.com"
	cdnSub := "github.githubassets.com"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><link rel="stylesheet" href="https://` + cdnSub + `/assets/foo.css">` +
			`<link rel="stylesheet" href="https://` + cdnParent + `/assets/bar.css"></html>`))
	}))
	defer upstream.Close()

	// Configure only the parent domain.
	if err := SetFallbackProxy(upstream.URL, false, []string{cdnParent}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fallbackProxy = nil; fallbackCDNHosts = nil })

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "my-site.com"
	rec := httptest.NewRecorder()
	ServeFallback(rec, req)

	body := rec.Body.String()
	// Subdomain URL should be rewritten with the full subdomain host.
	wantSub := "http://my-site.com" + cdnPathPrefix + cdnSub + "/assets/foo.css"
	if !strings.Contains(body, wantSub) {
		t.Errorf("body should contain %q\nbody: %s", wantSub, body)
	}
	// Parent domain URL should also be rewritten.
	wantParent := "http://my-site.com" + cdnPathPrefix + cdnParent + "/assets/bar.css"
	if !strings.Contains(body, wantParent) {
		t.Errorf("body should contain %q\nbody: %s", wantParent, body)
	}
	// Original URLs should not appear.
	if strings.Contains(body, "https://"+cdnSub) {
		t.Errorf("body should not contain https://%s\nbody: %s", cdnSub, body)
	}
	if strings.Contains(body, "https://"+cdnParent) {
		t.Errorf("body should not contain https://%s\nbody: %s", cdnParent, body)
	}
}

// TestSetFallbackProxy_CDNNonMatchingSubdomain verifies that a host that
// merely ends with the configured CDN domain string (but is not a true
// subdomain) is NOT matched. For example, "notgithubassets.com" should not
// match "githubassets.com".
func TestSetFallbackProxy_CDNNonMatchingSubdomain(t *testing.T) {
	cdnParent := "githubassets.com"
	fakeHost := "notgithubassets.com"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><link href="https://` + fakeHost + `/foo.css"></html>`))
	}))
	defer upstream.Close()

	if err := SetFallbackProxy(upstream.URL, false, []string{cdnParent}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fallbackProxy = nil; fallbackCDNHosts = nil })

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "my-site.com"
	rec := httptest.NewRecorder()
	ServeFallback(rec, req)

	body := rec.Body.String()
	// The fake host URL should NOT be rewritten.
	if !strings.Contains(body, "https://"+fakeHost+"/foo.css") {
		t.Errorf("body should contain unchanged %q URL\nbody: %s", fakeHost, body)
	}
	if strings.Contains(body, cdnPathPrefix+fakeHost) {
		t.Errorf("body should not contain /__cdn__/%s\nbody: %s", fakeHost, body)
	}
}
