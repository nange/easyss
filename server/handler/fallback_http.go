package handler

import (
	"fmt"
	"hash/fnv"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// 本文件实现自动生成页面的 "HTTP 真实性层"：真实静态站点（nginx 之类）会对
// 每个文件发送 Content-Length、Last-Modified、ETag 与 Accept-Ranges，并在
// If-None-Match / If-Modified-Since 命中时返回 304。Go 默认既不发这些头，
// 默认的 chunked 传输也不是 nginx 的行为——它们本身就是可观测特征。
//
// 这一层只作用于自动生成模式：运营者提供的目录/自定义页面和反向代理响应
// 完全不受影响。

var httpTimeFormat = http.TimeFormat

// prepareFallbackResponse 设置自动生成页面的响应头，并根据条件请求决定是否
// 直接写出 304。它向 body 写入请求返回 true；返回 false 表示已经写出 304，
// 调用方必须立即返回。
func prepareFallbackResponse(w http.ResponseWriter, r *http.Request, body []byte,
	lastModified time.Time, status int) bool {
	etag := strongETag(body)
	lastModified = lastModified.UTC().Truncate(time.Second)

	if isNotModified(r, etag, lastModified) {
		// 304 不得携带消息体，也不应重复整套实体头；只回验证器即可。
		w.Header().Set("Server", "nginx")
		w.Header().Set("ETag", etag)
		w.WriteHeader(http.StatusNotModified)
		return false
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Server", "nginx")
	w.Header().Set("Accept-Ranges", "bytes")
	w.Header().Set("Last-Modified", lastModified.Format(httpTimeFormat))
	w.Header().Set("ETag", etag)
	// 显式设置 Content-Length：否则 HTTP/1.1 会退化为 chunked，
	// 而真实 nginx 对静态文件总是给出长度。
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(status)
	return true
}

// isNotModified 按照 RFC 7232 的优先级判断条件请求是否命中：
// If-None-Match 优先于 If-Modified-Since，且后者只在没有前者时才参与判断。
func isNotModified(r *http.Request, etag string, lastModified time.Time) bool {
	if inm := r.Header.Get("If-None-Match"); inm != "" {
		return etagMatch(inm, etag)
	}
	if ims := r.Header.Get("If-Modified-Since"); ims != "" {
		if t, err := http.ParseTime(ims); err == nil {
			// 两侧都截断到秒：HTTP 日期没有亚秒精度，
			// 不截断会让同一秒内的比较结果随纳秒抖动。
			return !lastModified.Truncate(time.Second).After(t.Truncate(time.Second))
		}
	}
	return false
}

// etagMatch 解析 If-None-Match 头。这里实现弱比较：比较时忽略 W/ 前缀，
// 因为本包只生成强验证器。
func etagMatch(header, etag string) bool {
	for candidate := range strings.SplitSeq(header, ",") {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}
		if candidate == "*" || strings.TrimPrefix(candidate, "W/") == etag {
			return true
		}
	}
	return false
}

// strongETag 由页面字节派生一个强验证器。内容在部署内是稳定的，
// 因此 ETag 也稳定；跨部署则随着调色板与文案一起变化。
func strongETag(body []byte) string {
	h := fnv.New64a()
	h.Write(body)
	return fmt.Sprintf(`"%x"`, h.Sum64())
}
