package main

import (
	"log"
	"net/http"

	"github.com/nange/webproxy/http/handler"
)

const port = ":8080"

func main() {
	proxyHandler := handler.New()

	log.Println("Start http proxy serving on port", port)

	log.Fatal(http.ListenAndServe(port, proxyHandler))
}
