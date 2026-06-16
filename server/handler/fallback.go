package handler

import (
	"html/template"
	"net/http"
	"sync"
)

var fallbackTemplate = template.Must(template.New("fallback").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ .Title }}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 0; background: #f5f5f5; color: #333; }
        header { background: #2c3e50; color: white; padding: 20px; text-align: center; }
        nav { background: #34495e; padding: 10px; text-align: center; }
        nav a { color: #ecf0f1; margin: 0 15px; text-decoration: none; }
        main { max-width: 800px; margin: 40px auto; padding: 20px; background: white; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        footer { text-align: center; padding: 20px; color: #7f8c8d; font-size: 14px; }
    </style>
</head>
<body>
    <header>
        <h1>{{ .Title }}</h1>
        <p>{{ .Subtitle }}</p>
    </header>
    <nav>
        <a href="/">{{ .NavHome }}</a>
        <a href="/about">{{ .NavAbout }}</a>
        <a href="/contact">{{ .NavContact }}</a>
    </nav>
    <main>
        <h2>{{ .Heading }}</h2>
        <p>{{ .Content }}</p>
        <p>{{ .Content2 }}</p>
    </main>
    <footer>
        <p>{{ .Footer }}</p>
    </footer>
</body>
</html>`))

type FallbackData struct {
	Title      string
	Subtitle   string
	NavHome    string
	NavAbout   string
	NavContact string
	Heading    string
	Content    string
	Content2   string
	Footer     string
}

var defaultFallbackHTML []byte
var fallbackOnce sync.Once

func SetFallbackHTML(html []byte) {
	if len(html) == 0 {
		return
	}
	defaultFallbackHTML = append(defaultFallbackHTML[:0], html...)
}

func generateDefaultFallbackHTML() {
	if len(defaultFallbackHTML) > 0 {
		return
	}
	defaultFallbackData := FallbackData{
		Title:      "Welcome to Our Site",
		Subtitle:   "Your trusted source for information",
		NavHome:    "Home",
		NavAbout:   "About",
		NavContact: "Contact",
		Heading:    "Welcome",
		Content:    "Thank you for visiting our website. We are dedicated to providing the best service possible.",
		Content2:   "Please browse our site to learn more about what we offer.",
		Footer:     "2024 All rights reserved.",
	}

	var buf bytesWriter
	buf.buf = make([]byte, 0, 4096)
	fallbackTemplate.Execute(&buf, defaultFallbackData) //nolint:errcheck
	defaultFallbackHTML = buf.buf
}

type bytesWriter struct {
	buf []byte
}

func (w *bytesWriter) Write(p []byte) (int, error) {
	w.buf = append(w.buf, p...)
	return len(p), nil
}

func ServeFallback(w http.ResponseWriter, r *http.Request) {
	fallbackOnce.Do(generateDefaultFallbackHTML)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Server", "nginx")
	w.WriteHeader(http.StatusOK)
	w.Write(defaultFallbackHTML) //nolint:errcheck
}
