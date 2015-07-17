package handler

import (
	"io"
	"log"
	"net/http"
)

var httpClient = &http.Client{}

func handleHttp(rw http.ResponseWriter, req *http.Request) {
	log.Printf("host: %s, scheme: %s, path: %s, url.Host: %s", req.Host, req.URL.Scheme, req.URL.Path, req.URL.Host)

	log.Println("request method:", req.Method)

	req.RequestURI = ""

	res, err := httpClient.Do(req)

	if err != nil {
		log.Printf("http: proxy error: %v", err)
		rw.WriteHeader(http.StatusInternalServerError)

		return
	}

	defer res.Body.Close()

	header := rw.Header()

	for k, vv := range res.Header {
		for _, v := range vv {
			header.Add(k, v)
		}
	}

	rw.WriteHeader(res.StatusCode)

	if res.Body != nil {
		io.Copy(rw, res.Body)
	}

}
