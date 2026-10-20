package handler

import (
	"fmt"
	"hash/fnv"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// 本文件实现自动生成页面的 "HTTP 真实性层"：真实静态站点会发 Content-Length、
// Last-Modified、ETag、Accept-Ranges 并在条件请求命中时返回 304，而 Go 默认的
// chunked 传输本身就是可观测特征。该层只作用于自动生成模式，目录/自定义/反代不受影响。

var httpTimeFormat = http.TimeFormat

// prepareFallbackResponse 设置自动生成页面的响应头并按条件请求决定是否直接写 304。
// 返回 true 表示调用方还要写 body；返回 false 表示 304 已写出，调用方必须立即返回。
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
	// 显式设置 Content-Length：否则 HTTP/1.1 会退化为 chunked，而真实 nginx 对静态文件
	// 总是给出长度。
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(status)
	return true
}

// isNotModified 按 RFC 7232 判断条件请求：If-None-Match 优先于 If-Modified-Since。
func isNotModified(r *http.Request, etag string, lastModified time.Time) bool {
	if inm := r.Header.Get("If-None-Match"); inm != "" {
		return etagMatch(inm, etag)
	}
	if ims := r.Header.Get("If-Modified-Since"); ims != "" {
		if t, err := http.ParseTime(ims); err == nil {
			// 两侧都截断到秒：HTTP 日期没有亚秒精度。
			return !lastModified.Truncate(time.Second).After(t.Truncate(time.Second))
		}
	}
	return false
}

// etagMatch 解析 If-None-Match 头，做弱比较：比较时忽略 W/ 前缀，因为本包只生成强验证器。
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

// strongETag 由页面字节派生强验证器：内容在部署内稳定，因此 ETag 也稳定。
func strongETag(body []byte) string {
	h := fnv.New64a()
	h.Write(body)
	return fmt.Sprintf(`"%x"`, h.Sum64())
}
