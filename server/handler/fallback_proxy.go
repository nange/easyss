package handler

// Reverse-proxy fallback mode: forwards non-proxy requests to an upstream
// HTTP service (e.g. a local nginx) and rewrites the upstream's HTML, CSP,
// Location and Set-Cookie headers so the client stays on the client-facing
// origin. Split out of fallback.go.

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/util"
)

// setFallbackProxy configures a reverse proxy to forward non-proxy requests to
// an upstream HTTP service (e.g. a local nginx). When set, this takes the
// highest priority over all other fallback modes.
// Pass an empty string to disable.
//
// Unlike httputil.NewSingleHostReverseProxy, this uses Rewrite + SetURL so
// that req.Host is set to the upstream host (some upstreams — e.g. GitHub —
// return a 301 redirect to their canonical host when the Host header does not
// match). A ModifyResponse hook rewrites Location headers that point at the
// upstream host back to the client-facing host (read from the request
// context, injected by ServeFallback), so that 3xx redirects issued by the
// upstream do not cause the browser's address bar to jump to the upstream.
//
// If preserveHost is true, the client-facing Host header is forwarded to the
// upstream unchanged (i.e. SetURL is still called for scheme/host/path but
// Out.Host is restored to the original request Host). This is useful when
// proxying to a local nginx that uses server_name-based virtual host routing
// and expects to see the public-facing Host.
//
// HTML response bodies and the Content-Security-Policy header are always
// rewritten so that absolute URLs pointing at the upstream host (e.g.
// https://github.com/...) are replaced with the client-facing origin (e.g.
// https://my-site.com/...). This is needed for upstreams like GitHub that
// embed absolute URLs in turbo-frame src attributes or CSP directives, which
// otherwise cause CSP violations and direct browser connections to the
// upstream.
//
// cdnDomains is a list of additional hosts (e.g. "github.githubassets.com")
// whose resources should also be proxied through the client-facing origin.
// Requests to /__cdn__/<host>/<path> are routed to https://<host>/<path>, and
// HTML/CSP content referencing these hosts is rewritten to the /__cdn__/
// prefix form. Pass nil/empty to disable CDN proxying.
//
// Accept-Encoding negotiation: the proxy intersects the client's
// Accept-Encoding with the encodings it can handle (gzip and identity). If
// the client accepts gzip, the upstream request advertises "identity, gzip"
// so the upstream may compress large responses; gzip HTML is decompressed for
// rewriting and re-compressed before returning to the client. If the client
// does not accept gzip, the upstream request advertises "identity" only, so
// no decompression/recompression is needed.
func setFallbackProxy(targetURL string, preserveHost bool, cdnDomains []string) error {
	if targetURL == "" {
		fallbackProxy = nil
		fallbackCDNHosts = nil
		return nil
	}
	u, err := url.Parse(targetURL)
	if err != nil {
		return fmt.Errorf("parse fallback proxy url: %w", err)
	}
	targetHost := u.Host

	// Build the allowed CDN host set (lowercased for case-insensitive match).
	cdnSet := make(map[string]bool, len(cdnDomains))
	for _, d := range cdnDomains {
		cdnSet[strings.ToLower(strings.TrimSpace(d))] = true
	}
	fallbackCDNHosts = cdnSet

	fallbackProxy = &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			// Check if this is a CDN-routed request (/__cdn__/<host>/...).
			if cdnTarget, ok := routeCDN(pr, cdnSet); ok {
				// CDN request: route to the extracted CDN host. Set
				// URL fields directly (not SetURL) to avoid path joining.
				pr.Out.URL.Scheme = cdnTarget.Scheme
				pr.Out.URL.Host = cdnTarget.Host
				pr.Out.URL.Path = cdnTarget.Path
				pr.Out.URL.RawQuery = cdnTarget.RawQuery
				pr.Out.Host = cdnTarget.Host
				setAcceptEncoding(pr)
				return
			}

			// Normal request: route to the main upstream.
			pr.SetURL(u)
			if preserveHost {
				pr.Out.Host = pr.In.Host
			}
			setAcceptEncoding(pr)
			// Rewrite Origin and Referer request headers so the upstream
			// sees its own origin. Without this, Rails CSRF protection
			// (e.g. GitHub) rejects POST requests because the Origin header
			// is "https://my-site.com" instead of "https://github.com",
			// resulting in HTTP 422.
			rewriteRequestOriginReferrer(pr.Out, pr.In.Host, u)
		},
		ModifyResponse: func(resp *http.Response) error {
			// Determine the effective target host for this response: if it
			// was a CDN request, use the CDN host; otherwise use the main
			// upstream host.
			effectiveHost := targetHost
			if cdnHost, ok := cdnHostFromRequest(resp.Request, cdnSet); ok {
				effectiveHost = cdnHost
			}
			if err := rewriteLocationHeader(resp, effectiveHost); err != nil {
				return err
			}
			rewriteSetCookieHeaders(resp, effectiveHost)
			// Rewrite CSP header independently of body rewriting, so that
			// CSP is always processed even if the body cannot be read
			// (e.g. unsupported Content-Encoding like br).
			rewriteCSPHeader(resp, effectiveHost)
			return rewriteResponseBody(resp, effectiveHost)
		},
	}
	return nil
}

// setAcceptEncoding sets the outbound Accept-Encoding header based on what
// the client accepts, intersected with what the proxy can handle (gzip and
// identity).
func setAcceptEncoding(pr *httputil.ProxyRequest) {
	clientAE := pr.In.Header.Get("Accept-Encoding")
	if clientAcceptsGzip(clientAE) {
		pr.Out.Header.Set("Accept-Encoding", "identity, gzip")
	} else {
		pr.Out.Header.Set("Accept-Encoding", "identity")
	}
}

// cdnHostMatches reports whether host matches any configured CDN domain.
// It matches exactly (host == domain) or as a subdomain (host's parent
// domain is in the set), using util.SubDomains for parent-domain extraction.
// For example, if "githubassets.com" is configured, both "githubassets.com"
// and "github.githubassets.com" match, but "notgithubassets.com" does not.
func cdnHostMatches(host string, cdnSet map[string]bool) bool {
	if cdnSet[strings.ToLower(host)] {
		return true
	}
	for _, sub := range util.SubDomains(host) {
		if cdnSet[strings.ToLower(sub)] {
			return true
		}
	}
	return false
}

// routeCDN checks if the outbound request path starts with the CDN path
// prefix (/__cdn__/<host>/...) and, if the extracted host is in the allowed
// set (exact or subdomain match), returns the upstream URL to proxy to.
// Returns ok=false if the request is not a CDN-routed request or the host
// is not allowed.
func routeCDN(pr *httputil.ProxyRequest, cdnSet map[string]bool) (*url.URL, bool) {
	path := pr.Out.URL.Path
	if !strings.HasPrefix(path, cdnPathPrefix) {
		return nil, false
	}
	rest := path[len(cdnPathPrefix):]
	// Extract the host: everything up to the next "/".
	slashIdx := strings.Index(rest, "/")
	var host, restPath string
	if slashIdx < 0 {
		host = rest
		restPath = ""
	} else {
		host = rest[:slashIdx]
		restPath = rest[slashIdx:]
	}
	if host == "" {
		return nil, false
	}
	if !cdnHostMatches(host, cdnSet) {
		return nil, false
	}
	target := &url.URL{
		Scheme: "https",
		Host:   host,
		Path:   restPath,
	}
	if pr.Out.URL.RawQuery != "" {
		target.RawQuery = pr.Out.URL.RawQuery
	}
	return target, true
}

// cdnHostFromRequest extracts the CDN host from a request's URL path if it
// is a /__cdn__/ request with an allowed host (exact or subdomain match).
// Returns ok=false otherwise.
func cdnHostFromRequest(req *http.Request, cdnSet map[string]bool) (string, bool) {
	if req == nil {
		return "", false
	}
	path := req.URL.Path
	if !strings.HasPrefix(path, cdnPathPrefix) {
		return "", false
	}
	rest := path[len(cdnPathPrefix):]
	before, _, ok := strings.Cut(rest, "/")
	var host string
	if !ok {
		host = rest
	} else {
		host = before
	}
	if host == "" || !cdnHostMatches(host, cdnSet) {
		return "", false
	}
	return host, true
}

// clientAcceptsGzip reports whether the given Accept-Encoding header value
// indicates that gzip is acceptable to the client (q-value > 0). The wildcard
// "*" is treated as accepting gzip.
func clientAcceptsGzip(acceptEncoding string) bool {
	if acceptEncoding == "" {
		return false
	}
	for part := range strings.SplitSeq(acceptEncoding, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		coding := part
		q := 1.0
		for i, p := range strings.Split(part, ";") {
			p = strings.TrimSpace(p)
			if i == 0 {
				coding = p
				continue
			}
			if strings.HasPrefix(p, "q=") {
				if v, err := strconv.ParseFloat(p[2:], 64); err == nil {
					q = v
				}
			}
		}
		if (coding == "gzip" || coding == "*") && q > 0 {
			return true
		}
	}
	return false
}

// rewriteRequestOriginReferrer rewrites the Origin and Referer headers on the
// outbound request so the upstream sees its own origin instead of the
// proxy's client-facing host. This is required for upstreams that validate
// the Origin header as part of CSRF protection (e.g. Rails/GitHub return HTTP
// 422 when the Origin doesn't match). Only headers whose host equals the
// client-facing host are rewritten; headers pointing at other hosts are left
// untouched.
func rewriteRequestOriginReferrer(out *http.Request, clientHost string, upstream *url.URL) {
	for _, hdr := range []string{"Origin", "Referer"} {
		val := out.Header.Get(hdr)
		if val == "" {
			continue
		}
		parsed, err := url.Parse(val)
		if err != nil {
			continue
		}
		if parsed.Host != clientHost {
			continue
		}
		parsed.Scheme = upstream.Scheme
		parsed.Host = upstream.Host
		out.Header.Set(hdr, parsed.String())
	}
}

// rewriteLocationHeader rewrites a 3xx Location header so that browser
// redirects stay on the proxy's address. It handles two cases:
//  1. Location pointing at the main upstream host → rewrite to client-facing host
//  2. Location pointing at a configured CDN domain → rewrite to /__cdn__/<host>/<path>
//
// Relative-path Locations (e.g. "/login") and Locations pointing at other
// hosts are left untouched.
func rewriteLocationHeader(resp *http.Response, targetHost string) error {
	loc := resp.Header.Get("Location")
	if loc == "" {
		return nil
	}
	locURL, err := url.Parse(loc)
	if err != nil {
		// Malformed Location — leave it untouched and let the client decide.
		return nil
	}
	if locURL.Host == "" {
		return nil
	}

	ctx := resp.Request.Context()
	origHost, _ := ctx.Value(ctxOrigHost).(string)
	if origHost == "" {
		return nil
	}
	origScheme, _ := ctx.Value(ctxOrigScheme).(string)
	if origScheme == "" {
		origScheme = "https"
	}

	// Case 1: Location points at the main upstream host.
	if locURL.Host == targetHost {
		locURL.Scheme = origScheme
		locURL.Host = origHost
		resp.Header.Set("Location", locURL.String())
		return nil
	}

	// Case 2: Location points at a configured CDN domain (or subdomain).
	// Rewrite to /__cdn__/<host>/<path> so the browser follows the
	// redirect through the proxy instead of going directly to the CDN.
	// This handles cases like GitHub's /raw/ URLs redirecting to
	// raw.githubusercontent.com.
	if cdnHostMatches(locURL.Host, fallbackCDNHosts) {
		cdnHost := locURL.Host
		locURL.Scheme = origScheme
		locURL.Host = origHost
		locURL.Path = cdnPathPrefix + cdnHost + locURL.Path
		resp.Header.Set("Location", locURL.String())
		return nil
	}

	return nil
}

// rewriteSetCookieHeaders rewrites Set-Cookie response headers so that cookies
// set by the upstream for its own domain are accepted by the browser visiting
// the proxy's host. Without this, an upstream like GitHub that sets
// "Domain=github.com" on its session cookies would be rejected by the browser
// (the page origin is my-site.com, not a subdomain of github.com), causing
// features that depend on session cookies — such as CSRF tokens in the login
// form — to fail with HTTP 422.
//
// For each Set-Cookie header whose Domain attribute equals the upstream host
// (case-insensitive, leading dot ignored), the Domain attribute is removed
// entirely so the cookie becomes a host-only cookie bound to the proxy's host.
// Cookies with a Domain pointing at a different host are left untouched.
func rewriteSetCookieHeaders(resp *http.Response, targetHost string) {
	cookies := resp.Header["Set-Cookie"]
	if len(cookies) == 0 {
		return
	}

	targetHostLower := strings.ToLower(strings.TrimPrefix(targetHost, "."))

	rewritten := make([]string, 0, len(cookies))
	for _, raw := range cookies {
		parts := strings.Split(raw, ";")
		for i, part := range parts {
			p := strings.TrimSpace(part)
			if len(p) <= 7 { // len("Domain=") == 7
				continue
			}
			if !strings.EqualFold(p[:7], "Domain=") {
				continue
			}
			domain := strings.TrimSpace(p[7:])
			domain = strings.TrimPrefix(domain, ".")
			if strings.EqualFold(domain, targetHostLower) {
				// Remove the Domain attribute so the cookie becomes a
				// host-only cookie for the proxy's host.
				rewrittenParts := append(append([]string{}, parts[:i]...), parts[i+1:]...)
				raw = strings.Join(rewrittenParts, ";")
				break
			}
		}
		rewritten = append(rewritten, raw)
	}
	resp.Header["Set-Cookie"] = rewritten
}

// rewriteCSP rewrites a Content-Security-Policy header value so that source
// expressions referencing the upstream host are replaced with the
// client-facing origin. It handles three forms:
//  1. Scheme-prefixed: "https://github.com/path" → "https://my-site.com/path"
//  2. Scheme-prefixed http: "http://github.com/path" → "https://my-site.com/path"
//  3. Bare host: "github.com/assets-cdn/worker/" → "my-site.com/assets-cdn/worker/"
//
// Bare-host replacement is done token-by-token (CSP source lists are
// space-separated) to avoid accidentally replacing substrings of other hosts
// (e.g. "api.github.com" or "github.githubassets.com").
func rewriteCSP(csp, targetHost, origOrigin string) string {
	// Replace scheme-prefixed forms first.
	csp = strings.ReplaceAll(csp, "https://"+targetHost, origOrigin)
	csp = strings.ReplaceAll(csp, "http://"+targetHost, origOrigin)

	// Replace bare-host forms (no scheme prefix). CSP source lists are
	// space-separated, so split on space and replace tokens that start
	// with the target host followed by "/" or end exactly at the target
	// host. This avoids matching substrings of other hosts like
	// "api.github.com" or "github.githubassets.com".
	origHost := strings.TrimPrefix(origOrigin, "http://")
	origHost = strings.TrimPrefix(origHost, "https://")
	parts := strings.Split(csp, " ")
	for i, part := range parts {
		// Strip trailing ";" (CSP directive separator) so it doesn't
		// interfere with host matching, then reattach it after.
		suffix := ""
		if strings.HasSuffix(part, ";") {
			suffix = ";"
			part = strings.TrimRight(part, ";")
		}
		if part == targetHost || strings.HasPrefix(part, targetHost+"/") {
			parts[i] = strings.Replace(part, targetHost, origHost, 1) + suffix
		}
	}
	return strings.Join(parts, " ")
}

// cdnURLRegexpCache caches compiled regexps for CDN domain patterns so we
// don't recompile on every response.
var cdnURLRegexpCache sync.Map // cdnHost string → *regexp.Regexp

// rewriteCDNURLs replaces absolute URLs (http and https) pointing at any
// configured CDN domain or its subdomains with the /__cdn__/<host> prefix
// form. For example, if "githubassets.com" is configured:
//
//	https://github.githubassets.com/assets/foo.css
//	→ https://my-site.com/__cdn__/github.githubassets.com/assets/foo.css
//
//	https://githubassets.com/assets/bar.css
//	→ https://my-site.com/__cdn__/githubassets.com/assets/bar.css
//
// The original host (including subdomain) is preserved in the /__cdn__/ path
// so that the proxy can route to the correct upstream.
func rewriteCDNURLs(body []byte, origOrigin string, cdnHosts map[string]bool) []byte {
	// Iterate in a stable order so the result does not depend on Go's map
	// iteration order when two configured hosts can match the same URL.
	hosts := make([]string, 0, len(cdnHosts))
	for cdnHost := range cdnHosts {
		hosts = append(hosts, cdnHost)
	}
	slices.Sort(hosts)

	for _, cdnHost := range hosts {
		re := getCdnURLRegexp(cdnHost)
		replaced := re.ReplaceAllFunc(body, func(match []byte) []byte {
			// The match is "https://<full-host>/" or "https://<full-host>:".
			// Extract the full host (everything between "://" and the
			// trailing "/" or ":").
			s := string(match)
			_, after, _ := strings.Cut(s, "://")
			rest := after
			// Trim trailing "/" or ":" to get the host.
			fullHost := rest
			if last := fullHost[len(fullHost)-1]; last == '/' || last == ':' {
				fullHost = fullHost[:len(fullHost)-1]
			}
			// Reconstruct: origOrigin + /__cdn__/<full-host> + trailing char.
			trailing := string(rest[len(fullHost):])
			return []byte(origOrigin + cdnPathPrefix + fullHost + trailing)
		})
		body = replaced
	}
	return body
}

// getCdnURLRegexp returns a compiled regexp that matches "https://<host>" or
// "http://<host>" where <host> is the configured CDN domain or any of its
// subdomains. The regexp is cached for reuse.
//
// The pattern matches the scheme and host only (not the path), and requires
// the host to be followed by "/" or ":" (port) or to be at a word boundary
// to avoid matching "notgithubassets.com" when the configured host is
// "githubassets.com".
func getCdnURLRegexp(cdnHost string) *regexp.Regexp {
	if cached, ok := cdnURLRegexpCache.Load(cdnHost); ok {
		return cached.(*regexp.Regexp)
	}
	escaped := regexp.QuoteMeta(cdnHost)
	// Match "https://" or "http://" followed by zero or more subdomain labels
	// then the CDN host. Zero or more (not "at most one") is required for the
	// rewriting to agree with cdnHostMatches, which accepts arbitrary depth:
	// a URL like "a.b.cdn.example.com" is routed through the proxy there, so
	// it must also be rewritten here or the assets leak to the real CDN.
	// The host must be followed by "/" or ":" (port) — captured as a trailing
	// group so it is not consumed by the match.
	pattern := `https?://(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.)*` + escaped + `(?:/|:)`
	re := regexp.MustCompile(pattern)
	cdnURLRegexpCache.Store(cdnHost, re)
	return re
}

// rewriteCDNInCSP rewrites a Content-Security-Policy header value so that
// source expressions referencing any configured CDN domain (or its
// subdomains) are replaced with the /__cdn__/<host>/ prefix form. This
// handles both scheme-prefixed forms (e.g. "https://github.githubassets.com")
// and bare-host forms (e.g. "github.githubassets.com/assets/").
//
// For example, if "githubassets.com" is configured:
//
//	https://github.githubassets.com → https://my-site.com/__cdn__/github.githubassets.com/ https://github.githubassets.com
//	github.githubassets.com/assets/ → my-site.com/__cdn__/github.githubassets.com/assets/ github.githubassets.com/assets/
//
// A trailing "/" is added when the original token had no path (bare host),
// because CSP path matching requires a trailing "/" to match sub-paths.
//
// The original CDN host token is PRESERVED alongside the rewritten form.
// This is necessary because JavaScript code may dynamically construct URLs
// pointing at the original CDN host (e.g. by string concatenation), which
// cannot be caught by body rewriting. Without the original host in CSP,
// these JS-initiated requests would be blocked (blocked:csp). Keeping the
// original host allows the request to go through (directly to the CDN),
// trading some privacy for functionality.
//
// The full host (including subdomain) is preserved in the /__cdn__/ path.
func rewriteCDNInCSP(csp, origScheme, origHost string, cdnHosts map[string]bool) string {
	origOrigin := origScheme + "://" + origHost
	parts := strings.Split(csp, " ")
	for i, part := range parts {
		// CSP directives are separated by ";", which may stick to the
		// end of a token after space-splitting (e.g.
		// "https://github.githubassets.com;"). Strip and preserve the
		// trailing ";" so it doesn't break URL parsing or host matching.
		suffix := ""
		if strings.HasSuffix(part, ";") {
			suffix = ";"
			part = strings.TrimRight(part, ";")
		}

		// Check if this is a scheme-prefixed URL.
		if strings.HasPrefix(part, "https://") || strings.HasPrefix(part, "http://") {
			u, err := url.Parse(part)
			if err != nil || u.Host == "" {
				continue
			}
			if !cdnHostMatches(u.Host, cdnHosts) {
				continue
			}
			// Reconstruct: origOrigin + /__cdn__/<full-host> + path + query.
			// If the original had no path, add "/" so CSP matches sub-paths.
			pathQuery := u.Path
			if pathQuery == "" {
				pathQuery = "/"
			}
			if u.RawQuery != "" {
				pathQuery += "?" + u.RawQuery
			}
			rewritten := origOrigin + cdnPathPrefix + u.Host + pathQuery
			// Preserve the original token so JS-constructed URLs to the
			// CDN host are not blocked by CSP.
			parts[i] = rewritten + " " + part + suffix
			continue
		}
		// Bare-host form: check if the token starts with a CDN host.
		host := part
		hasPath := false
		if slashIdx := strings.Index(part, "/"); slashIdx >= 0 {
			host = part[:slashIdx]
			hasPath = true
		}
		if host == "" {
			continue
		}
		if !cdnHostMatches(host, cdnHosts) {
			continue
		}
		// Replace the host portion with my-site.com/__cdn__/<full-token>.
		// If the original had no path, add "/" for CSP sub-path matching.
		// Preserve the original token so JS-constructed URLs to the CDN
		// host are not blocked by CSP.
		var rewritten string
		if !hasPath {
			rewritten = origHost + cdnPathPrefix + part + "/"
		} else {
			rewritten = origHost + cdnPathPrefix + part
		}
		parts[i] = rewritten + " " + part + suffix
	}
	return strings.Join(parts, " ")
}

// rewriteCSPHeader rewrites the Content-Security-Policy response header
// independently of body rewriting. This ensures CSP is always processed even
// when the response body cannot be read (e.g. unsupported Content-Encoding
// like br) or is not HTML. Without this, browsers may block sub-resources
// (CSS, JS, workers) loaded via /__cdn__/ paths because the CSP still
// references the original upstream/CDN hosts.
func rewriteCSPHeader(resp *http.Response, targetHost string) {
	csp := resp.Header.Get("Content-Security-Policy")
	if csp == "" {
		return
	}
	ctx := resp.Request.Context()
	origHost, _ := ctx.Value(ctxOrigHost).(string)
	if origHost == "" {
		return
	}
	origScheme, _ := ctx.Value(ctxOrigScheme).(string)
	if origScheme == "" {
		origScheme = "https"
	}
	origOrigin := origScheme + "://" + origHost
	csp = rewriteCSP(csp, targetHost, origOrigin)
	csp = rewriteCDNInCSP(csp, origScheme, origHost, fallbackCDNHosts)
	resp.Header.Set("Content-Security-Policy", csp)
}

// isRewritableContentType reports whether a response with the given
// Content-Type should have its body rewritten for URL substitution. Only
// HTML is rewritable; JavaScript is not because JS often constructs URLs
// dynamically (string concatenation) which cannot be caught by body
// rewriting, and scanning large JS files wastes CPU.
func isRewritableContentType(ct string) bool {
	ct = strings.ToLower(strings.TrimSpace(ct))
	// Strip any parameters (e.g. "; charset=utf-8").
	if idx := strings.Index(ct, ";"); idx >= 0 {
		ct = strings.TrimSpace(ct[:idx])
	}
	return ct == "text/html"
}

// rewriteResponseBody reads an HTML response body and replaces absolute URLs
// pointing at the upstream host (both http and https variants) with the
// client-facing origin, so that browser-initiated requests (e.g. Turbo frame
// fetches, <a> links, <form> actions) stay on the proxy instead of going
// directly to the upstream. The Content-Security-Policy response header is
// similarly rewritten (see rewriteCSPHeader). Non-HTML responses are passed
// through unchanged.
//
// The upstream request's Accept-Encoding is set to "identity, gzip" (when the
// client accepts gzip) or "identity" (otherwise), so the upstream may return
// either plain text or gzip-compressed content; gzip is transparently
// decompressed before rewriting. After rewriting, if the client accepts gzip,
// the response is re-compressed with gzip before being returned; otherwise it
// is sent uncompressed.
func rewriteResponseBody(resp *http.Response, targetHost string) error {
	// Only rewrite HTML and JavaScript responses.
	ct := resp.Header.Get("Content-Type")
	if !isRewritableContentType(ct) {
		return nil
	}

	// Read the body, decompressing gzip if necessary. From here on the body
	// has been consumed: every failure path must put a body back, otherwise
	// the reverse proxy would copy from an already-closed body and truncate
	// the response while the upstream Content-Length stayed in place.
	enc := resp.Header.Get("Content-Encoding")
	var body []byte

	switch enc {
	case "", "identity":
		var err error
		body, err = io.ReadAll(resp.Body)
		resp.Body.Close() //nolint:errcheck
		if err != nil {
			restoreFailedBody(resp, body, err)
			return nil
		}
	case "gzip":
		gr, gerr := gzip.NewReader(resp.Body)
		if gerr != nil {
			resp.Body.Close() //nolint:errcheck
			restoreFailedBody(resp, nil, gerr)
			return nil
		}
		var err error
		body, err = io.ReadAll(gr)
		gr.Close()        //nolint:errcheck
		resp.Body.Close() //nolint:errcheck
		if err != nil {
			restoreFailedBody(resp, body, err)
			return nil
		}
	default:
		// Unsupported encoding (br, deflate, etc.) — skip rewriting and
		// leave the untouched body in place.
		return nil
	}

	return rewriteBodyContent(resp, targetHost, body)
}

// restoreFailedBody reinstates a body that could not be fully read or
// decompressed, keeping the bytes that were actually obtained and dropping
// the now-wrong Content-Encoding so the client receives a consistent (if
// partial) response instead of a truncated one announced with a stale
// Content-Length.
func restoreFailedBody(resp *http.Response, body []byte, err error) {
	log.Debug("[FALLBACK] body read failed, passing through what was read", "err", err, "bytes", len(body))
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
	resp.Header.Del("Content-Encoding")
}

// rewriteBodyContent rewrites absolute upstream URLs and CDN host references
// in the decoded body, then re-compresses it when the client accepts gzip.
func rewriteBodyContent(resp *http.Response, targetHost string, body []byte) error {
	// Get the client-facing host/scheme from the request context.
	ctx := resp.Request.Context()
	origHost, _ := ctx.Value(ctxOrigHost).(string)
	if origHost == "" {
		// No client-facing host available — return body as-is.
		resp.Body = io.NopCloser(bytes.NewReader(body))
		return nil
	}
	origScheme, _ := ctx.Value(ctxOrigScheme).(string)
	if origScheme == "" {
		origScheme = "https"
	}

	// Replace absolute URLs: both http and https variants of the upstream
	// host are replaced with the client-facing origin.
	origOrigin := origScheme + "://" + origHost
	replaced := body
	replaced = bytes.ReplaceAll(replaced, []byte("http://"+targetHost), []byte(origOrigin))
	replaced = bytes.ReplaceAll(replaced, []byte("https://"+targetHost), []byte(origOrigin))

	// Replace CDN domain URLs with /__cdn__/<host> prefix form so that
	// browser requests for static assets (CSS, JS, images) hosted on CDN
	// domains are routed through the proxy instead of going directly to
	// the CDN host. This matches both the configured domain exactly and
	// any subdomain (e.g. "githubassets.com" matches both
	// "githubassets.com" and "github.githubassets.com").
	replaced = rewriteCDNURLs(replaced, origOrigin, fallbackCDNHosts)

	// Note: Content-Security-Policy header rewriting is handled
	// independently by rewriteCSPHeader in ModifyResponse, not here,
	// so that CSP is always processed even when the body cannot be read.

	// Re-compress with gzip if the client accepts it, so we don't waste
	// bandwidth on the client<->proxy leg. Otherwise send uncompressed.
	origAE, _ := ctx.Value(ctxOrigAcceptEncoding).(string)
	if clientAcceptsGzip(origAE) {
		var buf bytes.Buffer
		gw := gzip.NewWriter(&buf)
		if _, werr := gw.Write(replaced); werr != nil {
			gw.Close() //nolint:errcheck
			// Fall back to uncompressed on error.
			resp.Body = io.NopCloser(bytes.NewReader(replaced))
			resp.ContentLength = int64(len(replaced))
			resp.Header.Set("Content-Length", strconv.Itoa(len(replaced)))
			resp.Header.Del("Content-Encoding")
			return nil
		}
		gw.Close() //nolint:errcheck
		resp.Body = io.NopCloser(bytes.NewReader(buf.Bytes()))
		resp.ContentLength = int64(buf.Len())
		resp.Header.Set("Content-Length", strconv.Itoa(buf.Len()))
		resp.Header.Set("Content-Encoding", "gzip")
		return nil
	}

	resp.Body = io.NopCloser(bytes.NewReader(replaced))
	resp.ContentLength = int64(len(replaced))
	resp.Header.Set("Content-Length", strconv.Itoa(len(replaced)))
	resp.Header.Del("Content-Encoding")
	return nil
}
