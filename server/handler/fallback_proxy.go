package handler

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

func (fb *Fallback) setProxy(targetURL string, preserveHost bool, cdnDomains []string) error {
	if targetURL == "" {
		fb.proxy = nil
		fb.cdnHosts = nil
		return nil
	}
	u, err := url.Parse(targetURL)
	if err != nil {
		return fmt.Errorf("parse fallback proxy url: %w", err)
	}
	targetHost := u.Host

	cdnSet := make(map[string]bool, len(cdnDomains))
	for _, d := range cdnDomains {
		cdnSet[strings.ToLower(strings.TrimSpace(d))] = true
	}
	fb.cdnHosts = cdnSet

	fb.proxy = &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			if cdnTarget, ok := routeCDN(pr, cdnSet); ok {
				// 直接写 URL 字段而不用 SetURL，避免它把 CDN 路径拼到原路径上。
				pr.Out.URL.Scheme = cdnTarget.Scheme
				pr.Out.URL.Host = cdnTarget.Host
				pr.Out.URL.Path = cdnTarget.Path
				pr.Out.URL.RawQuery = cdnTarget.RawQuery
				pr.Out.Host = cdnTarget.Host
				setAcceptEncoding(pr)
				return
			}

			pr.SetURL(u)
			if preserveHost {
				pr.Out.Host = pr.In.Host
			}
			setAcceptEncoding(pr)
			// 上游按 Origin 校验 CSRF（如 Rails）时，客户端可见的源站会让 POST 以 HTTP 422 失败。
			rewriteRequestOriginReferrer(pr.Out, pr.In.Host, u)
		},
		ModifyResponse: func(resp *http.Response) error {
			effectiveHost := targetHost
			if cdnHost, ok := cdnHostFromRequest(resp.Request, cdnSet); ok {
				effectiveHost = cdnHost
			}
			if err := rewriteLocationHeader(resp, effectiveHost, fb.cdnHosts); err != nil {
				return err
			}
			rewriteSetCookieHeaders(resp, effectiveHost)
			// CSP 头独立于正文重写，正文因 br 等编码无法读取时它仍会被处理。
			rewriteCSPHeader(resp, effectiveHost, fb.cdnHosts)
			return rewriteResponseBody(resp, effectiveHost, fb.cdnHosts)
		},
	}
	return nil
}

// 只向上游通告代理能处理的编码，未处理过的编码会让正文无法重写。
func setAcceptEncoding(pr *httputil.ProxyRequest) {
	clientAE := pr.In.Header.Get("Accept-Encoding")
	if clientAcceptsGzip(clientAE) {
		pr.Out.Header.Set("Accept-Encoding", "identity, gzip")
	} else {
		pr.Out.Header.Set("Accept-Encoding", "identity")
	}
}

// 报告 host 是与某个已配置域完全相等，还是它的子域。
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

// 从 /__cdn__/<host>/<path> 解析出要代理的上游 URL。
func routeCDN(pr *httputil.ProxyRequest, cdnSet map[string]bool) (*url.URL, bool) {
	path := pr.Out.URL.Path
	if !strings.HasPrefix(path, cdnPathPrefix) {
		return nil, false
	}
	rest := path[len(cdnPathPrefix):]
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

// q 值必须大于 0，通配符 "*" 视为接受 gzip。
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

// 把 Origin/Referer 改写成上游源站：上游按 Origin 校验 CSRF（如 Rails）时不改写会以 422 拒绝。
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

// 把指向上游主机或 CDN 域的 Location 改写到客户端可见的源站，否则浏览器会直接跳出代理；
// 相对路径与指向其他主机的 Location 保持原样。
func rewriteLocationHeader(resp *http.Response, targetHost string, cdnHosts map[string]bool) error {
	loc := resp.Header.Get("Location")
	if loc == "" {
		return nil
	}
	locURL, err := url.Parse(loc)
	if err != nil {
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

	if locURL.Host == targetHost {
		locURL.Scheme = origScheme
		locURL.Host = origHost
		resp.Header.Set("Location", locURL.String())
		return nil
	}

	// 指向 CDN 域的 Location 改写成 /__cdn__/ 前缀形式，让浏览器经由代理跟随重定向。
	if cdnHostMatches(locURL.Host, cdnHosts) {
		cdnHost := locURL.Host
		locURL.Scheme = origScheme
		locURL.Host = origHost
		locURL.Path = cdnPathPrefix + cdnHost + locURL.Path
		resp.Header.Set("Location", locURL.String())
		return nil
	}

	return nil
}

// 删掉 Domain 等于上游主机的 Set-Cookie 属性，把它变成 host-only cookie：页面源站是代理主机，
// 带 Domain 的 cookie 会被浏览器丢弃，登录与 CSRF token 随即以 HTTP 422 失败。
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
				rewrittenParts := append(append([]string{}, parts[:i]...), parts[i+1:]...)
				raw = strings.Join(rewrittenParts, ";")
				break
			}
		}
		rewritten = append(rewritten, raw)
	}
	resp.Header["Set-Cookie"] = rewritten
}

// 把 CSP 中带 scheme 前缀或裸主机形式的源表达式改成客户端可见的源站。裸主机按空格分隔的
// token 逐个比对，否则会连 "api.github.com" 这类子串一起替换掉。
func rewriteCSP(csp, targetHost, origOrigin string) string {
	csp = strings.ReplaceAll(csp, "https://"+targetHost, origOrigin)
	csp = strings.ReplaceAll(csp, "http://"+targetHost, origOrigin)

	origHost := strings.TrimPrefix(origOrigin, "http://")
	origHost = strings.TrimPrefix(origHost, "https://")
	parts := strings.Split(csp, " ")
	for i, part := range parts {
		// 末尾的 ";" 是指令分隔符，先摘下来再参与主机匹配。
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

// cdnURLRegexpCache 缓存已编译的正则，它按响应正文大小逐次扫描，不能每个响应都重编译。
var cdnURLRegexpCache sync.Map // cdnHost string → *regexp.Regexp（CDN 主机 → 正则）

// 把指向已配置 CDN 域的绝对 URL 改写成 /__cdn__/<host> 前缀形式，完整主机保留在路径里，代理
// 才能路由回正确的上游。
func rewriteCDNURLs(body []byte, origOrigin string, cdnHosts map[string]bool) []byte {
	// 固定遍历顺序，同一个 URL 被多个已配置主机匹配时结果不随 map 迭代顺序变化。
	hosts := make([]string, 0, len(cdnHosts))
	for cdnHost := range cdnHosts {
		hosts = append(hosts, cdnHost)
	}
	slices.Sort(hosts)

	for _, cdnHost := range hosts {
		re := getCdnURLRegexp(cdnHost)
		replaced := re.ReplaceAllFunc(body, func(match []byte) []byte {
			s := string(match)
			_, after, _ := strings.Cut(s, "://")
			rest := after
			fullHost := rest
			if last := fullHost[len(fullHost)-1]; last == '/' || last == ':' {
				fullHost = fullHost[:len(fullHost)-1]
			}
			trailing := string(rest[len(fullHost):])
			return []byte(origOrigin + cdnPathPrefix + fullHost + trailing)
		})
		body = replaced
	}
	return body
}

// 匹配 http(s)://<已配置域或其任意深度的子域>，主机后必须紧跟 "/" 或 ":"，否则配置
// "githubassets.com" 时会误匹配 "notgithubassets.com"。
func getCdnURLRegexp(cdnHost string) *regexp.Regexp {
	if cached, ok := cdnURLRegexpCache.Load(cdnHost); ok {
		return cached.(*regexp.Regexp)
	}
	escaped := regexp.QuoteMeta(cdnHost)
	// 子域必须允许任意深度，与 cdnHostMatches 保持一致：否则匹配得上的会被代理路由却没被
	// 改写，资源就直连真实 CDN 泄露出去。尾部 "/" 或 ":" 并入匹配以便原样保留。
	pattern := `https?://(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.)*` + escaped + `(?:/|:)`
	re := regexp.MustCompile(pattern)
	cdnURLRegexpCache.Store(cdnHost, re)
	return re
}

// 把 CSP 中指向已配置 CDN 域的源表达式改写成 /__cdn__/ 前缀形式并保留原始 token：删掉原始
// 主机，JS 动态拼出的 URL 会被 CSP 拦掉。缺路径的裸主机补末尾 "/"，否则覆盖不到子路径。
func rewriteCDNInCSP(csp, origScheme, origHost string, cdnHosts map[string]bool) string {
	origOrigin := origScheme + "://" + origHost
	parts := strings.Split(csp, " ")
	for i, part := range parts {
		// ";" 可能粘在 token 末尾并破坏 URL 解析，先摘下来再拼回。
		suffix := ""
		if strings.HasSuffix(part, ";") {
			suffix = ";"
			part = strings.TrimRight(part, ";")
		}

		if strings.HasPrefix(part, "https://") || strings.HasPrefix(part, "http://") {
			u, err := url.Parse(part)
			if err != nil || u.Host == "" {
				continue
			}
			if !cdnHostMatches(u.Host, cdnHosts) {
				continue
			}
			// 没有路径时补 "/"，否则 CSP 匹配不到子路径。
			pathQuery := u.Path
			if pathQuery == "" {
				pathQuery = "/"
			}
			if u.RawQuery != "" {
				pathQuery += "?" + u.RawQuery
			}
			rewritten := origOrigin + cdnPathPrefix + u.Host + pathQuery
			parts[i] = rewritten + " " + part + suffix
			continue
		}
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

// 独立于正文重写 CSP 头：正文读不出来（br 等编码）或不是 HTML 时，CSP 仍引用上游/CDN 主机，
// 浏览器会拦掉经 /__cdn__/ 加载的 CSS、JS 与 worker。
func rewriteCSPHeader(resp *http.Response, targetHost string, cdnHosts map[string]bool) {
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
	csp = rewriteCDNInCSP(csp, origScheme, origHost, cdnHosts)
	resp.Header.Set("Content-Security-Policy", csp)
}

// 只放行 HTML：JS 常用字符串拼接构造 URL，正文重写抓不到，扫描大文件也只是白耗 CPU。
func isRewritableContentType(ct string) bool {
	ct = strings.ToLower(strings.TrimSpace(ct))
	if idx := strings.Index(ct, ";"); idx >= 0 {
		ct = strings.TrimSpace(ct[:idx])
	}
	return ct == "text/html"
}

// 把 HTML 正文里指向上游主机的绝对 URL 换成客户端可见的源站，浏览器后续发起的 Turbo frame、
// <a>、<form> 请求才会继续经过代理。上游可能返回 gzip，重写前解压、返回前再按需压缩。
func rewriteResponseBody(resp *http.Response, targetHost string, cdnHosts map[string]bool) error {
	ct := resp.Header.Get("Content-Type")
	if !isRewritableContentType(ct) {
		return nil
	}

	// 正文从这里开始被读走，失败路径必须放回一个 body：反向代理从已关闭的 body 拷数据，
	// 客户端拿到的是截断的响应，而 Content-Length 仍是上游给的值。
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
		return nil
	}

	return rewriteBodyContent(resp, targetHost, body, cdnHosts)
}

// 用实际读到的字节重建 body 并去掉 Content-Encoding，让可能不完整的内容与 Content-Length
// 保持一致，而不是让客户端卡在截断的响应上。
func restoreFailedBody(resp *http.Response, body []byte, err error) {
	log.Debug("[FALLBACK] body read failed, passing through what was read", "err", err, "bytes", len(body))
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
	resp.Header.Del("Content-Encoding")
}

func rewriteBodyContent(resp *http.Response, targetHost string, body []byte, cdnHosts map[string]bool) error {
	ctx := resp.Request.Context()
	origHost, _ := ctx.Value(ctxOrigHost).(string)
	if origHost == "" {
		resp.Body = io.NopCloser(bytes.NewReader(body))
		return nil
	}
	origScheme, _ := ctx.Value(ctxOrigScheme).(string)
	if origScheme == "" {
		origScheme = "https"
	}

	origOrigin := origScheme + "://" + origHost
	replaced := body
	replaced = bytes.ReplaceAll(replaced, []byte("http://"+targetHost), []byte(origOrigin))
	replaced = bytes.ReplaceAll(replaced, []byte("https://"+targetHost), []byte(origOrigin))

	replaced = rewriteCDNURLs(replaced, origOrigin, cdnHosts)

	origAE, _ := ctx.Value(ctxOrigAcceptEncoding).(string)
	if clientAcceptsGzip(origAE) {
		var buf bytes.Buffer
		gw := gzip.NewWriter(&buf)
		if _, werr := gw.Write(replaced); werr != nil {
			gw.Close() //nolint:errcheck
			// 压缩失败就发未压缩的正文。
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
