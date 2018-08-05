package httpproxy

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// InMemoryResponse creates new HTTP response given arguments.
func InMemoryResponse(code int, header http.Header, body []byte) *http.Response {
	if header == nil {
		header = make(http.Header)
	}
	st := http.StatusText(code)
	if st != "" {
		st = " " + st
	}
	var bodyReadCloser io.ReadCloser
	var bodyContentLength = int64(-1)
	if body != nil {
		bodyReadCloser = ioutil.NopCloser(bytes.NewBuffer(body))
		bodyContentLength = int64(len(body))
	}
	return &http.Response{
		Status:        fmt.Sprintf("%d%s", code, st),
		StatusCode:    code,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        header,
		Body:          bodyReadCloser,
		ContentLength: bodyContentLength,
	}
}

// ServeResponse serves HTTP response to http.ResponseWriter.
func ServeResponse(w http.ResponseWriter, resp *http.Response) error {
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	h := w.Header()
	for k, v := range resp.Header {
		for _, v1 := range v {
			h.Add(k, v1)
		}
	}
	if h.Get("Date") == "" {
		//h.Set("Date", time.Now().UTC().Format(time.RFC1123))
		h.Set("Date", time.Now().UTC().Format("Mon, 2 Jan 2006 15:04:05")+" GMT")
	}
	if h.Get("Content-Type") == "" {
		h.Set("Content-Type", "text/plain; charset=utf-8")
	}
	if resp.ContentLength >= 0 {
		h.Set("Content-Length", strconv.FormatInt(resp.ContentLength, 10))
	} else {
		h.Del("Content-Length")
	}
	h.Del("Transfer-Encoding")
	te := ""
	if len(resp.TransferEncoding) > 0 {
		if len(resp.TransferEncoding) > 1 {
			return ErrUnsupportedTransferEncoding
		}
		te = resp.TransferEncoding[0]
	}
	switch te {
	case "":
		w.WriteHeader(resp.StatusCode)
		if resp.Body != nil {
			if _, err := io.Copy(w, resp.Body); err != nil {
				return err
			}
		}
	case "chunked":
		h.Add("Transfer-Encoding", "chunked")
		//h.Del("Content-Length")
		h.Set("Connection", "close")
		w.WriteHeader(resp.StatusCode)
		w2 := httputil.NewChunkedWriter(w)
		if resp.Body != nil {
			if _, err := io.Copy(w2, resp.Body); err != nil {
				return err
			}
		}
		if err := w2.Close(); err != nil {
			return err
		}
		if _, err := w.Write([]byte("\r\n")); err != nil {
			return err
		}
	default:
		return ErrUnsupportedTransferEncoding
	}
	return nil
}

// ServeInMemory serves HTTP response given arguments to http.ResponseWriter.
func ServeInMemory(w http.ResponseWriter, code int, header http.Header, body []byte) error {
	return ServeResponse(w, InMemoryResponse(code, header, body))
}

var hasPort = regexp.MustCompile(`:\d+$`)

func stripPort(s string) string {
	ix := strings.IndexRune(s, ':')
	if ix == -1 {
		return s
	}
	return s[:ix]
}

func removeProxyHeaders(r *http.Request) {
	// If no Accept-Encoding header exists, Transport will add the headers it can accept
	// and would wrap the response body with the relevant reader.
	r.Header.Del("Accept-Encoding")
	// curl can add that, see
	// https://jdebp.eu./FGA/web-proxy-connection-header.html
	r.Header.Del("Proxy-Connection")
	r.Header.Del("Proxy-Authenticate")
	r.Header.Del("Proxy-Authorization")
	// Connection, Authenticate and Authorization are single hop Header:
	// http://www.w3.org/Protocols/rfc2616/rfc2616.txt
	// 14.10 Connection
	//   The Connection general-header field allows the sender to specify
	//   options that are desired for that particular connection and MUST NOT
	//   be communicated by proxies over further connections.
	r.Header.Del("Connection")
}
