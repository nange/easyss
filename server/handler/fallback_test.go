package handler

import (
	"net/http"
	"net/http/httptest"
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
		"index.html":       "<h1>Home</h1>",
		"blog/post1.html":  "<h1>Post 1</h1>",
		"blog/post2.html":  "<h1>Post 2</h1>",
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
		"index.html":       "<h1>Home</h1>",
		"blog/index.html":  "<h1>Blog Home</h1>",
		"blog/post1.html":  "<h1>Post 1</h1>",
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
