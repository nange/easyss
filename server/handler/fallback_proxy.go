package handler

// 反向代理回退模式：把非代理请求转发给上游 HTTP 服务（如本地 nginx），
// 并重写上游的 HTML、CSP、Location 和 Set-Cookie 头，使客户端始终停留在
// 客户端可见的源站上。该文件从 fallback.go 中拆分而来。

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

// setFallbackProxy 配置一个反向代理，把非代理请求转发给上游 HTTP 服务
// （如本地 nginx）。一旦设置，它拥有高于所有其他回退模式的最高优先级。
// 传入空字符串可禁用。
//
// 与 httputil.NewSingleHostReverseProxy 不同，这里使用 Rewrite + SetURL，
// 使 req.Host 被设置为上游主机（有些上游——如 GitHub——在 Host 头不匹配时
// 会 301 重定向到其规范主机）。ModifyResponse 钩子会把指向上游主机的
// Location 头重写回客户端可见的主机（从请求上下文中读取，由 ServeFallback
// 注入），这样上游发出的 3xx 重定向不会让浏览器地址栏跳到上游。
//
// 如果 preserveHost 为 true，客户端可见的 Host 头会原样转发给上游
// （即仍然调用 SetURL 设置 scheme/host/path，但 Out.Host 恢复为原始请求的
// Host）。这在代理到使用 server_name 虚拟主机路由、期望看到公网 Host 的
// 本地 nginx 时很有用。
//
// HTML 响应体和 Content-Security-Policy 头总是被重写，使指向上游主机的
// 绝对 URL（如 https://github.com/...）被替换为客户端可见的源站
// （如 https://my-site.com/...）。对于 GitHub 这类会把绝对 URL 内嵌在
// turbo-frame 的 src 属性或 CSP 指令里的上游，这是必需的；否则会导致
// CSP 违规以及浏览器直连上游。
//
// cdnDomains 是额外主机（如 "github.githubassets.com"）的列表，这些主机的
// 资源也应该通过客户端可见的源站代理。对 /__cdn__/<host>/<path> 的请求会
// 路由到 https://<host>/<path>，并且 HTML/CSP 内容中引用这些主机的部分会
// 被重写为 /__cdn__/ 前缀形式。传入 nil/空列表可禁用 CDN 代理。
//
// Accept-Encoding 协商：代理把客户端的 Accept-Encoding 与自身支持的编码
// （gzip 和 identity）取交集。如果客户端接受 gzip，向上游的请求会通告
// "identity, gzip"，使上游可以对大响应进行压缩；gzip 的 HTML 会先解压以便
// 重写，返回给客户端前再重新压缩。如果客户端不接受 gzip，向上游的请求
// 只通告 "identity"，从而无需解压/再压缩。
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

	// 构建允许的 CDN 主机集合（统一转小写，以便不区分大小写地匹配）。
	cdnSet := make(map[string]bool, len(cdnDomains))
	for _, d := range cdnDomains {
		cdnSet[strings.ToLower(strings.TrimSpace(d))] = true
	}
	fallbackCDNHosts = cdnSet

	fallbackProxy = &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			// 检查这是否是一个 CDN 路由请求（/__cdn__/<host>/...）。
			if cdnTarget, ok := routeCDN(pr, cdnSet); ok {
				// CDN 请求：路由到提取出的 CDN 主机。直接设置
				// URL 字段（不用 SetURL）以避免路径拼接。
				pr.Out.URL.Scheme = cdnTarget.Scheme
				pr.Out.URL.Host = cdnTarget.Host
				pr.Out.URL.Path = cdnTarget.Path
				pr.Out.URL.RawQuery = cdnTarget.RawQuery
				pr.Out.Host = cdnTarget.Host
				setAcceptEncoding(pr)
				return
			}

			// 普通请求：路由到主上游。
			pr.SetURL(u)
			if preserveHost {
				pr.Out.Host = pr.In.Host
			}
			setAcceptEncoding(pr)
			// 重写 Origin 和 Referer 请求头，使上游看到的是它自己的源站。
			// 否则 Rails 的 CSRF 防护（如 GitHub）会因 Origin 头是
			// "https://my-site.com" 而非 "https://github.com" 而拒绝 POST 请求，
			// 导致 HTTP 422。
			rewriteRequestOriginReferrer(pr.Out, pr.In.Host, u)
		},
		ModifyResponse: func(resp *http.Response) error {
			// 确定该响应对应的有效目标主机：如果是 CDN 请求则用 CDN 主机，
			// 否则用主上游主机。
			effectiveHost := targetHost
			if cdnHost, ok := cdnHostFromRequest(resp.Request, cdnSet); ok {
				effectiveHost = cdnHost
			}
			if err := rewriteLocationHeader(resp, effectiveHost); err != nil {
				return err
			}
			rewriteSetCookieHeaders(resp, effectiveHost)
			// 独立于正文重写处理 CSP 头，这样即使正文无法读取
			// （如遇到 br 等不支持的 Content-Encoding），CSP 也总是被处理。
			rewriteCSPHeader(resp, effectiveHost)
			return rewriteResponseBody(resp, effectiveHost)
		},
	}
	return nil
}

// setAcceptEncoding 根据客户端接受的编码与代理能处理的编码（gzip 和 identity）
// 的交集，设置出站请求的 Accept-Encoding 头。
func setAcceptEncoding(pr *httputil.ProxyRequest) {
	clientAE := pr.In.Header.Get("Accept-Encoding")
	if clientAcceptsGzip(clientAE) {
		pr.Out.Header.Set("Accept-Encoding", "identity, gzip")
	} else {
		pr.Out.Header.Set("Accept-Encoding", "identity")
	}
}

// cdnHostMatches 报告 host 是否匹配任何已配置的 CDN 域。
// 匹配规则为完全相等（host == domain）或作为子域匹配（host 的父域在集合中），
// 使用 util.SubDomains 提取父域。
// 例如，如果配置了 "githubassets.com"，则 "githubassets.com" 和
// "github.githubassets.com" 都匹配，但 "notgithubassets.com" 不匹配。
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

// routeCDN 检查出站请求路径是否以 CDN 路径前缀（/__cdn__/<host>/...）开头，
// 如果提取出的主机在允许集合中（完全匹配或子域匹配），则返回要代理到的
// 上游 URL。如果请求不是 CDN 路由请求或主机不被允许，则返回 ok=false。
func routeCDN(pr *httputil.ProxyRequest, cdnSet map[string]bool) (*url.URL, bool) {
	path := pr.Out.URL.Path
	if !strings.HasPrefix(path, cdnPathPrefix) {
		return nil, false
	}
	rest := path[len(cdnPathPrefix):]
	// 提取主机：下一个 "/" 之前的部分。
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

// cdnHostFromRequest 如果请求是带有允许主机（完全匹配或子域匹配）的
// /__cdn__/ 请求，则从请求的 URL 路径中提取 CDN 主机；否则返回 ok=false。
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

// clientAcceptsGzip 报告给定的 Accept-Encoding 头值是否表明客户端接受 gzip
// （q 值 > 0）。通配符 "*" 视为接受 gzip。
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

// rewriteRequestOriginReferrer 重写出站请求上的 Origin 和 Referer 头，
// 使上游看到的是它自己的源站而不是代理的客户端可见主机。对于把 Origin 头
// 作为 CSRF 防护一部分进行校验的上游（如 Rails/GitHub 在 Origin 不匹配时
// 返回 HTTP 422），这是必需的。只重写主机等于客户端可见主机的头；
// 指向其他主机的头保持原样。
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

// rewriteLocationHeader 重写 3xx 响应的 Location 头，使浏览器重定向停留在
// 代理的地址上。它处理两种情况：
//  1. Location 指向主上游主机 → 重写为客户端可见的主机
//  2. Location 指向已配置的 CDN 域 → 重写为 /__cdn__/<host>/<path>
//
// 相对路径的 Location（如 "/login"）以及指向其他主机的 Location 保持原样。
func rewriteLocationHeader(resp *http.Response, targetHost string) error {
	loc := resp.Header.Get("Location")
	if loc == "" {
		return nil
	}
	locURL, err := url.Parse(loc)
	if err != nil {
		// Location 格式非法——保持原样，由客户端自行处理。
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

	// 情况 1：Location 指向主上游主机。
	if locURL.Host == targetHost {
		locURL.Scheme = origScheme
		locURL.Host = origHost
		resp.Header.Set("Location", locURL.String())
		return nil
	}

	// 情况 2：Location 指向已配置的 CDN 域（或其子域）。
	// 重写为 /__cdn__/<host>/<path>，使浏览器经由代理跟随重定向，
	// 而不是直接访问 CDN。这可以处理类似 GitHub 的 /raw/ URL
	// 重定向到 raw.githubusercontent.com 的情况。
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

// rewriteSetCookieHeaders 重写 Set-Cookie 响应头，使上游为其自身域设置的
// cookie 能被访问代理主机的浏览器接受。否则，像 GitHub 这样在会话 cookie 上
// 设置 "Domain=github.com" 的上游会被浏览器拒绝（页面源站是 my-site.com，
// 不是 github.com 的子域），导致依赖会话 cookie 的功能——如登录表单中的
// CSRF token——以 HTTP 422 失败。
//
// 对于每个 Domain 属性等于上游主机（不区分大小写，忽略前导点）的
// Set-Cookie 头，Domain 属性会被完全移除，使 cookie 变成绑定到代理主机的
// host-only cookie。Domain 指向其他主机的 cookie 保持原样。
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
			if len(p) <= 7 { // len("Domain=") == 7（"Domain=" 长度为 7）
				continue
			}
			if !strings.EqualFold(p[:7], "Domain=") {
				continue
			}
			domain := strings.TrimSpace(p[7:])
			domain = strings.TrimPrefix(domain, ".")
			if strings.EqualFold(domain, targetHostLower) {
				// 移除 Domain 属性，使 cookie 变成绑定到代理主机的
				// host-only cookie。
				rewrittenParts := append(append([]string{}, parts[:i]...), parts[i+1:]...)
				raw = strings.Join(rewrittenParts, ";")
				break
			}
		}
		rewritten = append(rewritten, raw)
	}
	resp.Header["Set-Cookie"] = rewritten
}

// rewriteCSP 重写 Content-Security-Policy 头的值，使引用上游主机的源表达式
// 被替换为客户端可见的源站。它处理三种形式：
//  1. 带 scheme 前缀："https://github.com/path" → "https://my-site.com/path"
//  2. 带 scheme 前缀的 http："http://github.com/path" → "https://my-site.com/path"
//  3. 裸主机："github.com/assets-cdn/worker/" → "my-site.com/assets-cdn/worker/"
//
// 裸主机替换按 token 逐个进行（CSP 源列表以空格分隔），以避免误替换其他主机
// 的子串（如 "api.github.com" 或 "github.githubassets.com"）。
func rewriteCSP(csp, targetHost, origOrigin string) string {
	// 先替换带 scheme 前缀的形式。
	csp = strings.ReplaceAll(csp, "https://"+targetHost, origOrigin)
	csp = strings.ReplaceAll(csp, "http://"+targetHost, origOrigin)

	// 替换裸主机形式（无 scheme 前缀）。CSP 源列表以空格分隔，
	// 因此按空格拆分，并替换以目标主机开头后跟 "/" 或恰好等于
	// 目标主机的 token。这样可以避免误匹配其他主机的子串，
	// 如 "api.github.com" 或 "github.githubassets.com"。
	origHost := strings.TrimPrefix(origOrigin, "http://")
	origHost = strings.TrimPrefix(origHost, "https://")
	parts := strings.Split(csp, " ")
	for i, part := range parts {
		// 去掉末尾的 ";"（CSP 指令分隔符），避免干扰主机匹配，之后再重新拼回。
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

// cdnURLRegexpCache 缓存已编译的 CDN 域模式正则表达式，避免每个响应都重新编译。
var cdnURLRegexpCache sync.Map // cdnHost string → *regexp.Regexp（CDN 主机 → 正则）

// rewriteCDNURLs 把指向任何已配置 CDN 域或其子域的绝对 URL（http 和 https）
// 替换为 /__cdn__/<host> 前缀形式。例如，如果配置了 "githubassets.com"：
//
//	https://github.githubassets.com/assets/foo.css
//	→ https://my-site.com/__cdn__/github.githubassets.com/assets/foo.css
//
//	https://githubassets.com/assets/bar.css
//	→ https://my-site.com/__cdn__/githubassets.com/assets/bar.css
//
// 原始主机（含子域）保留在 /__cdn__/ 路径中，以便代理能路由到正确的上游。
func rewriteCDNURLs(body []byte, origOrigin string, cdnHosts map[string]bool) []byte {
	// 按稳定顺序遍历，这样当两个已配置主机可能匹配同一个 URL 时，
	// 结果不会依赖 Go 的 map 迭代顺序。
	hosts := make([]string, 0, len(cdnHosts))
	for cdnHost := range cdnHosts {
		hosts = append(hosts, cdnHost)
	}
	slices.Sort(hosts)

	for _, cdnHost := range hosts {
		re := getCdnURLRegexp(cdnHost)
		replaced := re.ReplaceAllFunc(body, func(match []byte) []byte {
			// 匹配结果是 "https://<full-host>/" 或 "https://<full-host>:"。
			// 提取完整主机（"://" 与末尾 "/" 或 ":" 之间的部分）。
			s := string(match)
			_, after, _ := strings.Cut(s, "://")
			rest := after
			// 去掉末尾的 "/" 或 ":" 得到主机。
			fullHost := rest
			if last := fullHost[len(fullHost)-1]; last == '/' || last == ':' {
				fullHost = fullHost[:len(fullHost)-1]
			}
			// 重新拼接：origOrigin + /__cdn__/<full-host> + 尾部字符。
			trailing := string(rest[len(fullHost):])
			return []byte(origOrigin + cdnPathPrefix + fullHost + trailing)
		})
		body = replaced
	}
	return body
}

// getCdnURLRegexp 返回一个已编译的正则，匹配 "https://<host>" 或
// "http://<host>"，其中 <host> 是已配置的 CDN 域或其任意子域。正则会被缓存复用。
//
// 该模式只匹配 scheme 和主机（不匹配路径），并要求主机后紧跟 "/" 或 ":"（端口），
// 从而在配置的主机是 "githubassets.com" 时不会误匹配 "notgithubassets.com"。
func getCdnURLRegexp(cdnHost string) *regexp.Regexp {
	if cached, ok := cdnURLRegexpCache.Load(cdnHost); ok {
		return cached.(*regexp.Regexp)
	}
	escaped := regexp.QuoteMeta(cdnHost)
	// 匹配 "https://" 或 "http://" 后跟零个或多个子域标签，然后是 CDN 主机。
	// 必须是零个或多个（而不是"至多一个"），以与接受任意深度的 cdnHostMatches
	// 保持一致：像 "a.b.cdn.example.com" 这样的 URL 在那里会经由代理路由，
	// 因此这里也必须重写，否则资源会直连真实 CDN 泄露出去。
	// 主机后必须紧跟 "/" 或 ":"（端口），该字符作为尾部组包含在匹配中，
	// 替换时可以原样保留而不会丢失。
	pattern := `https?://(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.)*` + escaped + `(?:/|:)`
	re := regexp.MustCompile(pattern)
	cdnURLRegexpCache.Store(cdnHost, re)
	return re
}

// rewriteCDNInCSP 重写 Content-Security-Policy 头的值，使引用任何已配置
// CDN 域（或其子域）的源表达式被替换为 /__cdn__/<host>/ 前缀形式。
// 它同时处理带 scheme 前缀的形式（如 "https://github.githubassets.com"）
// 和裸主机形式（如 "github.githubassets.com/assets/"）。
//
// 例如，如果配置了 "githubassets.com"：
//
//	https://github.githubassets.com → https://my-site.com/__cdn__/github.githubassets.com/ https://github.githubassets.com
//	github.githubassets.com/assets/ → my-site.com/__cdn__/github.githubassets.com/assets/ github.githubassets.com/assets/
//
// 当原始 token 没有路径（裸主机）时会补一个末尾 "/"，因为 CSP 的路径匹配
// 需要末尾 "/" 才能匹配子路径。
//
// 原始 CDN 主机 token 会与重写后的形式一同保留。这是必要的：JavaScript
// 代码可能动态构造指向原始 CDN 主机的 URL（如字符串拼接），正文重写无法
// 捕获这类情况。如果 CSP 中没有原始主机，这些由 JS 发起的请求会被拦截
// （blocked:csp）。保留原始主机允许请求直接放行（直连 CDN），
// 以部分隐私换取功能可用。
//
// 完整主机（含子域）保留在 /__cdn__/ 路径中。
func rewriteCDNInCSP(csp, origScheme, origHost string, cdnHosts map[string]bool) string {
	origOrigin := origScheme + "://" + origHost
	parts := strings.Split(csp, " ")
	for i, part := range parts {
		// CSP 指令以 ";" 分隔，按空格拆分后 ";" 可能粘在 token 末尾
		// （如 "https://github.githubassets.com;"）。去掉并保留末尾的 ";"，
		// 避免它破坏 URL 解析或主机匹配。
		suffix := ""
		if strings.HasSuffix(part, ";") {
			suffix = ";"
			part = strings.TrimRight(part, ";")
		}

		// 检查这是否是带 scheme 前缀的 URL。
		if strings.HasPrefix(part, "https://") || strings.HasPrefix(part, "http://") {
			u, err := url.Parse(part)
			if err != nil || u.Host == "" {
				continue
			}
			if !cdnHostMatches(u.Host, cdnHosts) {
				continue
			}
			// 重新拼接：origOrigin + /__cdn__/<full-host> + path + query。
			// 如果原始 URL 没有路径，补上 "/"，使 CSP 能匹配子路径。
			pathQuery := u.Path
			if pathQuery == "" {
				pathQuery = "/"
			}
			if u.RawQuery != "" {
				pathQuery += "?" + u.RawQuery
			}
			rewritten := origOrigin + cdnPathPrefix + u.Host + pathQuery
			// 保留原始 token，使 JS 构造的指向 CDN 主机的 URL 不被 CSP 拦截。
			parts[i] = rewritten + " " + part + suffix
			continue
		}
		// 裸主机形式：检查 token 是否以 CDN 主机开头。
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
		// 用 my-site.com/__cdn__/<full-token> 替换主机部分。
		// 如果原始 token 没有路径，补上 "/" 以便 CSP 匹配子路径。
		// 保留原始 token，使 JS 构造的指向 CDN 主机的 URL 不被 CSP 拦截。
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

// rewriteCSPHeader 独立于正文重写处理 Content-Security-Policy 响应头。
// 这确保即使响应正文无法读取（如 br 等不支持的 Content-Encoding）或不是
// HTML，CSP 也总是被处理。否则，浏览器可能会拦截通过 /__cdn__/ 路径加载的
// 子资源（CSS、JS、worker），因为 CSP 仍然引用原始的上游/CDN 主机。
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

// isRewritableContentType 报告给定 Content-Type 的响应是否应重写正文以替换
// URL。只有 HTML 可以重写；JavaScript 不可以，因为 JS 经常动态构造 URL
// （字符串拼接），正文重写无法捕获，而且扫描大型 JS 文件会浪费 CPU。
func isRewritableContentType(ct string) bool {
	ct = strings.ToLower(strings.TrimSpace(ct))
	// 去掉任何参数（如 "; charset=utf-8"）。
	if idx := strings.Index(ct, ";"); idx >= 0 {
		ct = strings.TrimSpace(ct[:idx])
	}
	return ct == "text/html"
}

// rewriteResponseBody 读取 HTML 响应正文，把指向上游主机的绝对 URL
// （http 和 https 两种形式）替换为客户端可见的源站，使浏览器发起的请求
// （如 Turbo frame 抓取、<a> 链接、<form> 提交）停留在代理上而不是直连上游。
// Content-Security-Policy 响应头也会被类似地重写（见 rewriteCSPHeader）。
// 非 HTML 响应原样透传。
//
// 向上游请求的 Accept-Encoding 被设置为 "identity, gzip"（当客户端接受
// gzip 时）或 "identity"（否则），因此上游可能返回纯文本或 gzip 压缩内容；
// gzip 会在重写前被透明解压。重写后，如果客户端接受 gzip，响应在返回前会
// 用 gzip 重新压缩；否则以未压缩形式发送。
func rewriteResponseBody(resp *http.Response, targetHost string) error {
	// 只重写 HTML 响应。
	ct := resp.Header.Get("Content-Type")
	if !isRewritableContentType(ct) {
		return nil
	}

	// 读取正文，必要时解压 gzip。从这里开始正文已被读走：所有失败路径都必须
	// 放回一个 body，否则反向代理会从一个已关闭的 body 上拷贝数据，
	// 导致响应被截断而上游的 Content-Length 仍然保留。
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
		// 不支持的编码（br、deflate 等）——跳过重写，保留未动过的正文。
		return nil
	}

	return rewriteBodyContent(resp, targetHost, body)
}

// restoreFailedBody 恢复一个未能完整读取或解压的 body：保留实际获得的字节，
// 并去掉已不正确的 Content-Encoding，使客户端收到一致（尽管可能不完整）的
// 响应，而不是带有过期 Content-Length 的截断响应。
func restoreFailedBody(resp *http.Response, body []byte, err error) {
	log.Debug("[FALLBACK] body read failed, passing through what was read", "err", err, "bytes", len(body))
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
	resp.Header.Del("Content-Encoding")
}

// rewriteBodyContent 重写解码后正文中的上游绝对 URL 和 CDN 主机引用，
// 然后在客户端接受 gzip 时重新压缩。
func rewriteBodyContent(resp *http.Response, targetHost string, body []byte) error {
	// 从请求上下文获取客户端可见的主机/scheme。
	ctx := resp.Request.Context()
	origHost, _ := ctx.Value(ctxOrigHost).(string)
	if origHost == "" {
		// 没有可用的客户端可见主机——原样返回正文。
		resp.Body = io.NopCloser(bytes.NewReader(body))
		return nil
	}
	origScheme, _ := ctx.Value(ctxOrigScheme).(string)
	if origScheme == "" {
		origScheme = "https"
	}

	// 替换绝对 URL：上游主机的 http 和 https 两种形式都被替换为客户端可见的源站。
	origOrigin := origScheme + "://" + origHost
	replaced := body
	replaced = bytes.ReplaceAll(replaced, []byte("http://"+targetHost), []byte(origOrigin))
	replaced = bytes.ReplaceAll(replaced, []byte("https://"+targetHost), []byte(origOrigin))

	// 把 CDN 域 URL 替换为 /__cdn__/<host> 前缀形式，使浏览器对 CDN 域上
	// 静态资源（CSS、JS、图片）的请求经由代理路由，而不是直连 CDN 主机。
	// 这同时匹配配置的域本身和任意子域（如 "githubassets.com" 同时匹配
	// "githubassets.com" 和 "github.githubassets.com"）。
	replaced = rewriteCDNURLs(replaced, origOrigin, fallbackCDNHosts)

	// 注意：Content-Security-Policy 头的重写由 ModifyResponse 中的
	// rewriteCSPHeader 独立处理，不在这里做，这样即使正文无法读取，
	// CSP 也总是被处理。

	// 如果客户端接受 gzip 则用 gzip 重新压缩，避免在客户端<->代理这一段
	// 浪费带宽。否则以未压缩形式发送。
	origAE, _ := ctx.Value(ctxOrigAcceptEncoding).(string)
	if clientAcceptsGzip(origAE) {
		var buf bytes.Buffer
		gw := gzip.NewWriter(&buf)
		if _, werr := gw.Write(replaced); werr != nil {
			gw.Close() //nolint:errcheck
			// 出错时回退为未压缩发送。
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
