package easyss

import (
	"net/http"
	"strconv"

	log "github.com/sirupsen/logrus"
	"github.com/wzshiming/sysproxy"
)

func (ss *Easyss) LocalHttp() error {
	var addr string
	if ss.BindAll() {
		addr = ":" + strconv.Itoa(ss.LocalHTTPPort())
	} else {
		addr = "127.0.0.1:" + strconv.Itoa(ss.LocalHTTPPort())
	}
	log.Infof("starting local http-proxy server at %v", addr)

	server := &http.Server{Addr: addr, Handler: &httpProxy{ss: ss}}
	ss.SetHttpProxyServer(server)

	err := server.ListenAndServe()
	if err != nil {
		log.Warnf("local http proxy server:%s", err.Error())
	}

	return err
}

func (ss *Easyss) SetSysProxyOnHTTP() error {
	return sysproxy.OnHTTP(ss.LocalHttpAddr())
}

func (ss *Easyss) SetSysProxyOffHTTP() error {
	return sysproxy.OffHTTP()
}

type httpProxy struct {
	ss *Easyss
}

func (h *httpProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != "CONNECT" {
		http.Error(w, "This is a proxy server. Does not respond to non-proxy requests.", http.StatusBadRequest)
		return
	}

	hij, ok := w.(http.Hijacker)
	if !ok {
		log.Errorf("Connect: hijacking not supported")
		if r.Body != nil {
			defer r.Body.Close()
		}
		http.Error(w, "Connect: hijacking not supported", http.StatusInternalServerError)
		return
	}

	hijConn, _, err := hij.Hijack()
	if err != nil {
		log.Errorf("get hijack conn, err:%s", err.Error())
		return
	}
	if _, err := hijConn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n")); err != nil {
		log.Errorf("write hijack ok err:%s", err.Error())
		hijConn.Close()
		return
	}

	if err := h.ss.localRelay(hijConn, r.URL.Host); err != nil {
		log.Warnf("http local relay err:%s", err.Error())
	}
}
