package main

import (
	"log"
	"net/http"
	"proxy/handler"
)

const port = ":8080"

func main() {
	proxyHandler := handler.New()

	log.Println("Start http proxy serving on port", port)

	log.Fatal(http.ListenAndServe(port, proxyHandler))
}
