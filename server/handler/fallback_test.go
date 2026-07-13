package handler

import (
	"compress/gzip"
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"os"
	"path/filepath"
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
	if err := SetFallbackProxy("", false); err != nil {
		t.Fatalf("unexpected error for empty URL: %v", err)
	}
	if fallbackProxy != nil {
		t.Error("expected fallbackProxy to be nil after empty URL")
	}
}

func TestSetFallbackProxy_InvalidURL(t *testing.T) {
	if err := SetFallbackProxy("://invalid", false); err == nil {
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

	if err := SetFallbackProxy(upstream.URL, false); err != nil {
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

	if err := SetFallbackProxy(upstream.URL, false); err != nil {
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

	if err := SetFallbackTarget("", false); err != nil {
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

	if err := SetFallbackTarget("http://127.0.0.1:8080", false); err != nil {
		t.Fatal(err)
	}
	if fallbackProxy == nil {
		t.Error("expected fallbackProxy to be set for HTTP URL")
	}
}

func TestSetFallbackTarget_HTTPSURL(t *testing.T) {
	t.Cleanup(func() { fallbackProxy = nil })

	if err := SetFallbackTarget("https://example.com", false); err != nil {
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

	if err := SetFallbackTarget(dir, false); err != nil {
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

	if err := SetFallbackTarget(filePath, false); err != nil {
		t.Fatal(err)
	}
	if string(customFallback) != "<h1>Custom</h1>" {
		t.Errorf("got %q, want %q", string(customFallback), "<h1>Custom</h1>")
	}
}

func TestSetFallbackTarget_InvalidPath(t *testing.T) {
	if err := SetFallbackTarget("/nonexistent/path", false); err == nil {
		t.Error("expected error for nonexistent path")
	}
}

func TestSetFallbackTarget_ProxyEndToEnd(t *testing.T) {
	// Full integration: SetFallbackTarget with HTTP URL then serve a request.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("upstream:" + r.URL.Path))
	}))
	defer upstream.Close()

	if err := SetFallbackTarget(upstream.URL, false); err != nil {
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

	if err := SetFallbackProxy(upstream.URL, false); err != nil {
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

	if err := SetFallbackProxy(upstream.URL, false); err != nil {
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

	if err := SetFallbackProxy(upstream.URL, false); err != nil {
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

	if err := SetFallbackProxy(upstream.URL, false); err != nil {
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

	if err := SetFallbackProxy(upstream.URL, true); err != nil {
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

	if err := SetFallbackProxy(upstream.URL, true); err != nil {
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

	if err := SetFallbackProxy(upstream.URL, false); err != nil {
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

	if err := SetFallbackProxy(upstream.URL, false); err != nil {
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

	if err := SetFallbackProxy(upstream.URL, false); err != nil {
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

	if err := SetFallbackProxy(upstream.URL, false); err != nil {
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

// TestSetFallbackProxy_RewriteContentAcceptEncoding verifies that the upstream
// receives Accept-Encoding: "identity, gzip" so the upstream may compress.
func TestSetFallbackProxy_RewriteContentAcceptEncoding(t *testing.T) {
	var gotAE string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAE = r.Header.Get("Accept-Encoding")
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html></html>"))
	}))
	defer upstream.Close()

	if err := SetFallbackProxy(upstream.URL, false); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fallbackProxy = nil })

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "my-site.com"
	rec := httptest.NewRecorder()
	ServeFallback(rec, req)

	if gotAE != "identity, gzip" {
		t.Errorf("upstream received Accept-Encoding %q, want %q", gotAE, "identity, gzip")
	}
}
