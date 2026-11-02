package handler

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// 本文件实现自动生成资源的 "HTTP 真实性层"：真实静态站点会发 Content-Length、Last-Modified、
// ETag、Accept-Ranges，对 Range 请求回 206/416，并在条件请求命中时返回 304，而 Go 默认的
// chunked 传输本身就是可观测特征。该层只作用于自动生成模式，目录/自定义/反代不受影响。

// fallbackResource 是一份由本包生成、能走完整 HTTP 语义的资源（页面或图标）。
type fallbackResource struct {
	body         []byte
	contentType  string
	lastModified time.Time
	status       int
}

var (
	errRangeIgnored       = errors.New("range: ignored")
	errRangeUnsatisfiable = errors.New("range: unsatisfiable")
)

// serveFallbackResource 按条件请求与 Range 头写出资源，返回调用方还要写出的 body。
// 返回 nil 表示响应已经写出（304/416），调用方必须立即返回。
func serveFallbackResource(w http.ResponseWriter, r *http.Request, res fallbackResource) []byte {
	lastModified := res.lastModified.UTC().Truncate(time.Second)
	etag := staticETag(lastModified, len(res.body))

	if isNotModified(r, etag, lastModified) {
		// 304 不得携带消息体，也不应重复整套实体头；只回验证器即可。
		w.Header().Set("Server", "nginx")
		w.Header().Set("ETag", etag)
		w.WriteHeader(http.StatusNotModified)
		return nil
	}

	body, status := res.body, res.status
	if spec := r.Header.Get("Range"); spec != "" && status == http.StatusOK && ifRangeAllows(r, etag, lastModified) {
		start, length, err := parseByteRange(spec, int64(len(body)))
		switch {
		case errors.Is(err, errRangeUnsatisfiable):
			// 声明了 Accept-Ranges 就必须真的拒绝越界区间，而不是回整份内容。
			w.Header().Set("Server", "nginx")
			w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", len(body)))
			w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
			return nil
		case err == nil:
			w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, start+length-1, len(body)))
			body, status = body[start:start+length], http.StatusPartialContent
		}
	}

	w.Header().Set("Content-Type", res.contentType)
	w.Header().Set("Server", "nginx")
	w.Header().Set("Accept-Ranges", "bytes")
	w.Header().Set("Last-Modified", lastModified.Format(http.TimeFormat))
	w.Header().Set("ETag", etag)
	// 显式设置 Content-Length：否则 HTTP/1.1 会退化为 chunked，而真实 nginx 对静态资源
	// 总是给出长度。
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(status)
	return body
}

// ifRangeAllows 判断条件 Range 请求是否仍可按区间处理（RFC 9110 §13.1.5）：验证器不匹配时
// 服务器必须回整份响应。If-Range 的比较是强比较，弱验证器不匹配任何内容。
func ifRangeAllows(r *http.Request, etag string, lastModified time.Time) bool {
	spec := strings.TrimSpace(r.Header.Get("If-Range"))
	switch {
	case spec == "":
		return true
	case strings.HasPrefix(spec, "W/"):
		return false
	case strings.HasPrefix(spec, `"`):
		return spec == etag
	}
	t, err := http.ParseTime(spec)
	return err == nil && !lastModified.After(t)
}

// parseByteRange 解析单个 bytes 区间，返回起始偏移与长度。多区间与语法错误按
// errRangeIgnored 处理（RFC 9110 §14.2 允许服务器忽略 Range）；语法正确但越界返回
// errRangeUnsatisfiable，由调用方回 416。
func parseByteRange(spec string, size int64) (start, length int64, err error) {
	rest, ok := strings.CutPrefix(spec, "bytes=")
	if !ok {
		return 0, 0, errRangeIgnored
	}
	rest = strings.TrimSpace(rest)
	// 多区间需要 multipart/byteranges 响应；浏览器不会发，这里按允许的"忽略"处理。
	if strings.Contains(rest, ",") {
		return 0, 0, errRangeIgnored
	}
	first, last, ok := strings.Cut(rest, "-")
	if !ok {
		return 0, 0, errRangeIgnored
	}

	if first == "" {
		// 后缀区间 -N：取最后 N 个字节。
		n, convErr := strconv.ParseInt(last, 10, 64)
		if convErr != nil || n < 0 {
			return 0, 0, errRangeIgnored
		}
		if n == 0 || size == 0 {
			return 0, 0, errRangeUnsatisfiable
		}
		return max(size-n, 0), min(n, size), nil
	}

	from, convErr := strconv.ParseInt(first, 10, 64)
	if convErr != nil || from < 0 {
		return 0, 0, errRangeIgnored
	}
	to := size - 1
	if last != "" {
		if to, convErr = strconv.ParseInt(last, 10, 64); convErr != nil || to < from {
			return 0, 0, errRangeIgnored
		}
	}
	if from >= size {
		return 0, 0, errRangeUnsatisfiable
	}
	return from, min(to, size-1) - from + 1, nil
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

// staticETag 沿用 nginx 对静态文件的验证器形态 "<十六进制 mtime>-<十六进制长度>"：
// 十六进制内容摘要的形态是构建工具或应用框架的特征，与本站的静态站身份不符。
func staticETag(lastModified time.Time, size int) string {
	return fmt.Sprintf(`"%x-%x"`, lastModified.Unix(), size)
}
