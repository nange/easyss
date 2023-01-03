package easyss

import (
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/wzshiming/sysproxy"
)

func (ss *Easyss) LocalHttp() {
	var addr string
	if ss.BindAll() {
		addr = ":" + strconv.Itoa(ss.LocalHTTPPort())
	} else {
		addr = "127.0.0.1:" + strconv.Itoa(ss.LocalHTTPPort())
	}
	log.Infof("[HTTP_PROXY] starting local http-proxy server at %v", addr)

	server := &http.Server{Addr: addr, Handler: &httpProxy{ss: ss}}
	ss.SetHttpProxyServer(server)

	if err := server.ListenAndServe(); err != nil {
		log.Warnf("[HTTP_PROXY] local http-proxy server:%s", err.Error())
	}
}

func (ss *Easyss) SetSysProxyOnHTTP() error {
	if err := sysproxy.OnHTTP(ss.LocalHttpAddr()); err != nil {
		return err
	}
	return sysproxy.OnHTTPS(ss.LocalHttpAddr())
}

func (ss *Easyss) SetSysProxyOffHTTP() error {
	if err := sysproxy.OffHTTP(); err != nil {
		return err
	}
	return sysproxy.OffHTTPS()
}

type httpProxy struct {
	ss *Easyss
}

func (h *httpProxy) client() *http.Client {
	c := &http.Client{
		Transport: &http.Transport{
			Proxy: func(*http.Request) (*url.URL, error) {
				return url.Parse(h.ss.Socks5ProxyAddr())
			},
			DisableKeepAlives:   true,
			TLSHandshakeTimeout: 10 * time.Second,
			ForceAttemptHTTP2:   true,
			MaxConnsPerHost:     1,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return c
}

func (h *httpProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == "CONNECT" {
		h.doWithHijack(w, r)
		return
	}
	h.doWithNormal(w, r)
}

func (h *httpProxy) doWithHijack(w http.ResponseWriter, r *http.Request) {
	hij, ok := w.(http.Hijacker)
	if !ok {
		log.Errorf("[HTTP_PROXY] Connect: hijacking not supported")
		if r.Body != nil {
			defer r.Body.Close()
		}
		http.Error(w, "Connect: hijacking not supported", http.StatusInternalServerError)
		return
	}

	hijConn, _, err := hij.Hijack()
	if err != nil {
		log.Errorf("[HTTP_PROXY] get hijack conn, err:%s", err.Error())
		return
	}
	if _, err := hijConn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n")); err != nil {
		log.Errorf("[HTTP_PROXY] write hijack ok err:%s", err.Error())
		hijConn.Close()
		return
	}

	if err := h.ss.localRelay(hijConn, r.URL.Host); err != nil {
		log.Warnf("[HTTP_PROXY] local relay err:%s", err.Error())
	}
}

func (h *httpProxy) doWithNormal(w http.ResponseWriter, r *http.Request) {
	// the RequestURI field should be empty for http.Client Do func
	r.RequestURI = ""
	// delete some unuseful header
	r.Header.Del("Proxy-Connection")
	r.Header.Del("Proxy-Authenticate")
	r.Header.Del("Proxy-Authorization")
	if r.Header.Get("Connection") == "close" {
		r.Close = false
	}
	r.Header.Del("Connection")

	client := h.client()
	resp, err := client.Do(r)
	if err != nil {
		log.Warnf("[HTTP_PROXY] client do request err:%s", err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)

	if _, err = io.Copy(w, resp.Body); err != nil {
		log.Warnf("[HTTP_PROXY] copy bytes back to client err:%s", err.Error())
	}
	if err := resp.Body.Close(); err != nil {
		log.Warnf("[HTTP_PROXY] can't close response body err:%s", err.Error())
	}
}

func copyHeaders(dst, src http.Header) {
	for k, vs := range src {
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}
