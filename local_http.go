package easyss

import (
	"encoding/base64"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"

	"github.com/nange/easyss/v2/util/bytespool"
	log "github.com/sirupsen/logrus"
	"github.com/wzshiming/sysproxy"
)

type bufferPool struct{}

func (bp *bufferPool) Get() []byte {
	return bytespool.Get(RelayBufferSize)
}

func (bp *bufferPool) Put(buf []byte) {
	bytespool.MustPut(buf)
}

func (ss *Easyss) LocalHttp() {
	var addr string
	if ss.BindAll() {
		addr = ":" + strconv.Itoa(ss.LocalHTTPPort())
	} else {
		addr = "127.0.0.1:" + strconv.Itoa(ss.LocalHTTPPort())
	}
	log.Infof("[HTTP_PROXY] starting local http-proxy server at %v", addr)

	server := &http.Server{Addr: addr, Handler: newHTTPProxy(ss)}
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
	rp *httputil.ReverseProxy
}

func newHTTPProxy(ss *Easyss) *httpProxy {
	return &httpProxy{
		ss: ss,
		rp: &httputil.ReverseProxy{
			Rewrite: func(r *httputil.ProxyRequest) {},
			Transport: &http.Transport{
				Proxy: func(*http.Request) (*url.URL, error) {
					return url.Parse(ss.Socks5ProxyAddr())
				},
				TLSHandshakeTimeout: ss.TLSTimeout(),
			},
			BufferPool: &bufferPool{},
			ErrorHandler: func(rw http.ResponseWriter, r *http.Request, err error) {
				log.Warnf("[HTTP_PROXY] reverse proxy request: %s", err.Error())
				http.Error(rw, "Service unavailable", http.StatusServiceUnavailable)
			},
		},
	}
}

func (h *httpProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.ss.AuthUsername() != "" && h.ss.AuthPassword() != "" {
		username, password, ok := basicAuth(r)
		if !ok {
			log.Warnf("[HTTP_PROXY] username and password not provided")
			http.Error(w, "Proxy auth required", http.StatusProxyAuthRequired)
			return
		}
		if username != h.ss.AuthUsername() || password != h.ss.AuthPassword() {
			log.Warnf("[HTTP_PROXY] username or password is invalid")
			http.Error(w, "Request unauthorized", http.StatusUnauthorized)
			return
		}
	}
	if r.Method == "CONNECT" {
		h.doWithHijack(w, r)
		return
	}
	h.rp.ServeHTTP(w, r)
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

func basicAuth(r *http.Request) (username, password string, ok bool) {
	username, password, ok = r.BasicAuth()
	if ok {
		return
	}
	auth := r.Header.Get("Proxy-Authorization")
	if auth == "" {
		return
	}
	return parseBasicAuth(auth)
}

func parseBasicAuth(auth string) (username, password string, ok bool) {
	const prefix = "Basic "

	if len(auth) < len(prefix) || !strings.EqualFold(auth[:len(prefix)], prefix) {
		return "", "", false
	}
	c, err := base64.StdEncoding.DecodeString(auth[len(prefix):])
	if err != nil {
		return "", "", false
	}
	cs := string(c)
	username, password, ok = strings.Cut(cs, ":")
	if !ok {
		return "", "", false
	}
	return username, password, true
}
