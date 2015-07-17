package handler

import (
	"log"
	"net/http"
)

type ProxyHttpHandler struct {
}

func New() *ProxyHttpHandler {
	return &ProxyHttpHandler{}
}

func (phh *ProxyHttpHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	log.Printf("host: %s, scheme: %s, path: %s, url.Host: %s", req.Host, req.URL.Scheme, req.URL.Path, req.URL.Host)

	method := req.Method

	switch method {
	case "CONNECT":
		handleHttps(rw, req)
	default:
		handleHttp(rw, req)
	}

}
