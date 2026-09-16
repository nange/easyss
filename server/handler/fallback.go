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

	"github.com/nange/easyss/v3/stats"
)

// fallbackFS embeds the themed-page template, the theme definitions and the
// content pools (see assets/fallback). Keeping them out of Go source lets the
// pages be tuned without touching code; they are compiled into the binary, so
// a missing or malformed asset fails loudly at startup instead of at request
// time.
//
//go:embed assets/fallback/*
var fallbackFS embed.FS

// mustReadFallback reads an embedded asset, panicking on failure: the assets
// are compiled in, so a missing file is a build-time mistake that must
// surface immediately.
func mustReadFallback(name string) []byte {
	b, err := fallbackFS.ReadFile(name)
	if err != nil {
		panic(fmt.Sprintf("embedded fallback asset %s: %v", name, err))
	}
	return b
}

var fallbackTmpl = template.Must(template.New("fallback").Parse(string(mustReadFallback("assets/fallback/template.html"))))

// ---------------------------------------------------------------------------
// Theme definitions — each theme has CSS and site-level info.
// Themes are visually distinct: different color palettes, fonts, and layout
// parameters. One theme is randomly selected at startup per deployment.
// ---------------------------------------------------------------------------

type themeDef struct {
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
// Content pools — realistic, varied text for each page type.
// Content is selected via deterministic hash of the request path,
// so the same URL always gets the same content.
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
// Types for rendering
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
// Global state
// ---------------------------------------------------------------------------

// ctxKey is an unexported context key type used to pass the original client-
// facing Host and scheme from ServeFallback into the reverse proxy's
// ModifyResponse hook, so that Location headers pointing at the upstream host
// can be rewritten back to the client-facing host without leaking the upstream
// via X-Forwarded-Host.
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
	htmlCache      sync.Map // path string → []byte
	htmlCacheCount atomic.Int32

	// Directory-based multi-file fallback.
	fallbackPages map[string][]byte // path → HTML bytes (e.g. "/about" → <html>...)
	fallback404   []byte            // optional 404 page

	// Reverse proxy to upstream HTTP service (e.g. local nginx).
	fallbackProxy *httputil.ReverseProxy

	// Allowed CDN hosts for /__cdn__/<host>/... path-prefix routing.
	// Populated by setFallbackProxy from the cdnDomains config. Keys are
	// lowercased hostnames; a request to /__cdn__/github.githubassets.com/x
	// is only proxied if "github.githubassets.com" is in this set.
	fallbackCDNHosts map[string]bool
)

const (
	// maxCachedFallbackPages bounds the generated-page cache. The curated
	// paths (/, /about, ...) would use 9 entries; the rest of the budget
	// serves arbitrary (generic) paths so a scanner hitting random URLs
	// cannot force a template render on every single request. Once the cap
	// is reached, further distinct paths render without caching (a render is
	// a small template execution), so the cache can never grow unbounded.
	maxCachedFallbackPages = 320

	// cdnPathPrefix is the URL path prefix under which requests for
	// configured CDN domains are routed. A request to
	//   /__cdn__/github.githubassets.com/assets/foo.css
	// is proxied to
	//   https://github.githubassets.com/assets/foo.css
	cdnPathPrefix = "/__cdn__/"
)

// setFallbackHTML overrides the built-in fallback system with custom HTML.
// Must be called before the server starts accepting requests.
func setFallbackHTML(html []byte) {
	if len(html) == 0 {
		return
	}
	customFallback = make([]byte, len(html))
	copy(customFallback, html)
}

// setFallbackDir loads all .html files from a directory as multi-route fallback
// pages. File-to-path mapping:
//   - index.html         → "/"
//   - 404.html           → unmatched paths
//   - <name>.html        → "/<name>"
//   - <sub>/<name>.html  → "/<sub>/<name>"
//   - <sub>/index.html   → "/<sub>"
//
// Non-.html files are ignored. Must be called before the server starts
// accepting requests.
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

		// 404.html is special: stored for unmatched paths, not as a regular page.
		if strings.EqualFold(nameWithoutExt, "404") {
			page404 = content
			return nil
		}

		// Build URL path from relative file path.
		urlPath := "/" + filepath.ToSlash(strings.TrimSuffix(rel, ".html"))

		// index.html maps to parent directory (or "/" for root).
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

// SetFallbackTarget resolves a single fallback target string and configures the
// appropriate fallback mode. The target is interpreted as:
//   - ""                        → built-in themed auto-generated pages
//   - "http://..." / "https://..." → reverse proxy to an upstream HTTP service
//   - a directory path             → multi-file HTML fallback (setFallbackDir)
//   - a regular file path          → single-file custom HTML (setFallbackHTML)
//
// preserveHost and cdnDomains only affect the reverse-proxy mode (see
// setFallbackProxy); they are ignored for the directory/file/built-in modes.
func SetFallbackTarget(target string, preserveHost bool, cdnDomains []string) error {
	// Reset all fallback state.
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

// ServeFallback writes a fallback HTML page to the response.
// Priority (highest first):
//  0. Reverse proxy to upstream HTTP service (setFallbackProxy)
//  1. Directory-based multi-file fallback (setFallbackDir)
//  2. Single-file custom fallback (setFallbackHTML)
//  3. Auto-generated themed pages
func ServeFallback(w http.ResponseWriter, r *http.Request) {
	stats.RecordServerFallbackPage()
	initOnce.Do(func() {
		selectedTheme = themes[rand.IntN(len(themes))]
	})

	// Priority 0 (highest): reverse proxy to upstream HTTP service.
	if fallbackProxy != nil {
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		// Strip easyss-specific headers (e.g. x-es) before forwarding so the
		// upstream service never sees proxy protocol traces.
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

	// Priority 1: directory-based multi-file fallback.
	if len(fallbackPages) > 0 {
		content, ok := fallbackPages[cleanPath(r.URL.Path)]
		if !ok {
			content = fallback404
		}
		if !ok && len(content) == 0 {
			// No matching page and no 404.html — fall back to index.
			content = fallbackPages["/"]
		}
		if len(content) > 0 {
			w.Write(content) //nolint:errcheck
			return
		}
	}

	// Priority 2: single-file custom fallback.
	if len(customFallback) > 0 {
		w.Write(customFallback) //nolint:errcheck
		return
	}

	// Priority 3: auto-generated themed pages.
	w.Write(getOrRenderHTML(r.URL.Path)) //nolint:errcheck
}

// cleanPath normalizes a URL path for lookup: "/" stays "/", everything else
// gets its trailing slash removed.
func cleanPath(p string) string {
	if p == "" || p == "/" {
		return "/"
	}
	return strings.TrimRight(p, "/")
}

// ---------------------------------------------------------------------------
// Internal helpers
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

// resolveTitle returns the page title. If the content title is empty or just a
// space, the site name is used as a fallback.
func resolveTitle(title, siteName string) string {
	title = strings.TrimSpace(title)
	if title == "" {
		return siteName
	}
	return title
}
