package handler

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
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
	// boundary 是多区间响应的分隔串编号：只有真正写 multipart 时才递增。
	boundary *atomic.Uint64
}

var (
	errRangeIgnored       = errors.New("range: ignored")
	errRangeUnsatisfiable = errors.New("range: unsatisfiable")
)

// serveFallbackResource 按条件请求与 Range 头写出资源，返回调用方还要写出的 body。
// 返回 nil 表示响应已经写出（304/416/multipart），调用方必须立即返回。
func serveFallbackResource(w http.ResponseWriter, r *http.Request, res fallbackResource) []byte {
	lastModified := res.lastModified.UTC().Truncate(time.Second)
	etag := staticETag(lastModified, len(res.body))

	// 条件请求与 Range 只对 GET/HEAD 且会得到 200 的请求成立：对 POST 回 304/206 是 RFC 9110
	// §15.4.5 禁止、nginx 也不会给出的应答，扫描器凭"先 GET 取 ETag，再 POST 同一路径"即可识别。
	getOrHead := r.Method == http.MethodGet || r.Method == http.MethodHead

	if getOrHead && res.status == http.StatusOK && isNotModified(r, etag, lastModified) {
		// 304 不得携带消息体；nginx 对静态文件的 304 同样带 Last-Modified，与 ETag 同源才自洽。
		w.Header().Set("Server", "nginx")
		w.Header().Set("ETag", etag)
		w.Header().Set("Last-Modified", lastModified.Format(http.TimeFormat))
		w.WriteHeader(http.StatusNotModified)
		return nil
	}

	body, status := res.body, res.status
	if spec := r.Header.Get("Range"); spec != "" && getOrHead && status == http.StatusOK && ifRangeAllows(r, etag, lastModified) {
		ranges, err := parseByteRanges(spec, int64(len(body)))
		switch {
		case errors.Is(err, errRangeUnsatisfiable):
			// nginx 对语法错误与全区间越界一律 416，错误页与默认错误页同形。
			w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", len(body)))
			serveReject(w, http.StatusRequestedRangeNotSatisfiable)
			return nil
		case err == nil && len(ranges) > 1:
			serveMultipartRanges(w, res, lastModified, etag, ranges)
			return nil
		case err == nil:
			rg := ranges[0]
			w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", rg.start, rg.start+rg.length-1, len(body)))
			body, status = body[rg.start:rg.start+rg.length], http.StatusPartialContent
		}
	}

	w.Header().Set("Content-Type", res.contentType)
	w.Header().Set("Server", "nginx")
	// Accept-Ranges 只出现在 200 上（没有 Range 或 Range 被忽略）：206 走区间过滤器提前返回，不带这个头。
	if res.status == http.StatusOK && status == http.StatusOK {
		w.Header().Set("Accept-Ranges", "bytes")
	}
	// 实体头只随文件响应发出：nginx 的 header 过滤器对非 200/206/304 丢弃 Last-Modified，
	// 错误页也没有 ETag。
	if res.status == http.StatusOK {
		w.Header().Set("Last-Modified", lastModified.Format(http.TimeFormat))
		w.Header().Set("ETag", etag)
	}
	// 显式设置 Content-Length：否则 HTTP/1.1 会退化为 chunked，而真实 nginx 对静态资源
	// 总是给出长度。
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(status)
	return body
}

// serveMultipartRanges 按 nginx 的 multipart/byteranges 形状写出多个区间：每段以 CRLF 开头，
// 末段是闭合分隔串；分隔串复刻 nginx 的零填充临时编号（64 位平台 20 位）。Content-Length 必须
// 覆盖全部分隔串，客户端才能按长度读完。
func serveMultipartRanges(w http.ResponseWriter, res fallbackResource, lastModified time.Time, etag string, ranges []byteRange) {
	boundary := fmt.Sprintf("%020d", res.boundary.Add(1))
	var buf bytes.Buffer
	for _, rg := range ranges {
		fmt.Fprintf(&buf, "\r\n--%s\r\nContent-Type: %s\r\nContent-Range: bytes %d-%d/%d\r\n\r\n",
			boundary, res.contentType, rg.start, rg.start+rg.length-1, len(res.body))
		buf.Write(res.body[rg.start : rg.start+rg.length])
	}
	fmt.Fprintf(&buf, "\r\n--%s--\r\n", boundary)

	w.Header().Set("Server", "nginx")
	w.Header().Set("Content-Type", "multipart/byteranges; boundary="+boundary)
	w.Header().Set("Last-Modified", lastModified.Format(http.TimeFormat))
	w.Header().Set("ETag", etag)
	w.Header().Set("Content-Length", strconv.Itoa(buf.Len()))
	w.WriteHeader(http.StatusPartialContent)
	w.Write(buf.Bytes()) //nolint:errcheck
}

// ifRangeAllows 判断条件 Range 请求是否仍可按区间处理（RFC 9110 §13.1.5）：验证器不匹配时
// 服务器必须回整份响应。nginx 对日期验证器要求与 Last-Modified 精确相等，弱验证器不匹配任何内容。
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
	return err == nil && t.Unix() == lastModified.Unix()
}

// byteRange 是解析后的单个区间：start 为起始偏移，length 为字节数。
type byteRange struct{ start, length int64 }

// parseByteRanges 复刻 ngx_http_range_parse：单位大小写不敏感，空白只出现在 nginx 接受的位置，
// 语法错误与全区间越界返回 errRangeUnsatisfiable（nginx 一律 416），多区间交给调用方写 multipart。
func parseByteRanges(spec string, size int64) ([]byteRange, error) {
	// 短于 7 字节或不是 bytes 单位的 Range 被 nginx 整体忽略，其余解析错误才是 416。
	if len(spec) < 7 || !strings.EqualFold(spec[:6], "bytes=") {
		return nil, errRangeIgnored
	}

	rest := spec[6:]
	var ranges []byteRange
	var total int64
	for {
		rest = strings.TrimLeft(rest, " ")
		if rest == "" {
			return nil, errRangeUnsatisfiable
		}

		start, end, suffix, after, ok := parseRangeSpec(rest, size)
		if !ok {
			return nil, errRangeUnsatisfiable
		}
		rest = after

		if suffix {
			start = max(size-end, 0)
			end = size - 1
		}
		if end >= size {
			end = size
		} else {
			end++
		}

		switch {
		case start < end:
			ranges = append(ranges, byteRange{start: start, length: end - start})
			total += end - start
		case start == 0:
			// nginx 对起点为 0 的空区间退回整份内容（例如空文件上的 bytes=0-）。
			return nil, errRangeIgnored
		}

		if rest == "" {
			break
		}
		if rest[0] != ',' {
			return nil, errRangeUnsatisfiable
		}
		rest = rest[1:]
	}

	switch {
	case len(ranges) == 0:
		return nil, errRangeUnsatisfiable
	case len(ranges) == 1:
		return ranges, nil
	// nginx 拒绝为多区间付出超过整份内容 + 4KB 的代价（重叠/过多区间），此时退回整份内容。
	case total > size, total+int64(len(ranges))*256 > size+4096:
		return nil, errRangeIgnored
	}
	return ranges, nil
}

// parseRangeSpec 解析单个 range-spec。end 在开区间时是 size、后缀区间时是后缀长度，由调用方
// 换算；rest 指向 ',' 或空串。
func parseRangeSpec(s string, size int64) (start, end int64, suffix bool, rest string, ok bool) {
	if s[0] == '-' {
		end, rest, ok = scanRangeNumber(s[1:])
		if !ok {
			return 0, 0, false, "", false
		}
		rest = strings.TrimLeft(rest, " ")
		if rest != "" && rest[0] != ',' {
			return 0, 0, false, "", false
		}
		return 0, end, true, rest, true
	}

	start, rest, ok = scanRangeNumber(s)
	if !ok {
		return 0, 0, false, "", false
	}
	rest = strings.TrimLeft(rest, " ")
	if rest == "" || rest[0] != '-' {
		return 0, 0, false, "", false
	}
	rest = strings.TrimLeft(rest[1:], " ")
	if rest == "" || rest[0] == ',' {
		return start, size, false, rest, true
	}

	end, rest, ok = scanRangeNumber(rest)
	if !ok {
		return 0, 0, false, "", false
	}
	rest = strings.TrimLeft(rest, " ")
	if rest != "" && rest[0] != ',' {
		return 0, 0, false, "", false
	}
	return start, end, false, rest, true
}

// scanRangeNumber 读一段十进制数字；缺失或溢出都按语法错误处理（nginx 同样回 416）。
func scanRangeNumber(s string) (int64, string, bool) {
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	if i == 0 {
		return 0, "", false
	}
	n, err := strconv.ParseInt(s[:i], 10, 64)
	if err != nil {
		return 0, "", false
	}
	return n, s[i:], true
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
