package handler

import (
	"io"
	"log"
	"net"
	"net/http"
)

func handleHttps(rw http.ResponseWriter, req *http.Request) {
	hij, ok := rw.(http.Hijacker)
	if !ok {
		panic("httpserver does not support hijacking")
	}

	proxyConn, _, err := hij.Hijack()

	if err != nil {
		panic("Cannot hijack connection " + err.Error())
	}

	targetConn, err := net.Dial("tcp", req.Host)
	if err != nil {
		if _, err := io.WriteString(rw, "HTTP/1.1 502 Bad Gateway\r\n\r\n"); err != nil {
			log.Printf("Error responding to client: %s", err)
		}
		proxyConn.Close()
		return
	}

	proxyConn.Write([]byte("HTTP/1.0 200 OK\r\n\r\n"))

	go copyConn(targetConn, proxyConn)
	go copyConn(proxyConn, targetConn)

}

func copyConn(dst, src net.Conn) {
	connOK := true

	if _, err := io.Copy(dst, src); err != nil {
		connOK = false
		log.Printf("Error copy to client. %s", err)
	}

	if err := src.Close(); err != nil && connOK {
		log.Printf("Error closeing: %s", err)
	}

}
