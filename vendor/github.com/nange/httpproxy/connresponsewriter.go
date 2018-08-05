package httpproxy

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
)

// ConnResponseWriter implements http.ResponseWriter interface to use hijacked
// HTTP connection.
type ConnResponseWriter struct {
	Conn        net.Conn
	mu          sync.Mutex
	err         error
	header      http.Header
	headersSent bool
}

// NewConnResponseWriter returns a new ConnResponseWriter.
func NewConnResponseWriter(conn net.Conn) *ConnResponseWriter {
	return &ConnResponseWriter{Conn: conn, header: make(http.Header)}
}

// Header returns the header map that will be sent by WriteHeader.
func (c *ConnResponseWriter) Header() http.Header {
	return c.header
}

// Write writes the data to the connection as part of an HTTP reply.
func (c *ConnResponseWriter) Write(body []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writeHeader(http.StatusOK)
	if c.err != nil {
		return 0, c.err
	}
	n, err := c.Conn.Write(body)
	if err != nil {
		c.err = err
	}
	return n, err
}

// WriteHeader sends an HTTP response header with status code.
func (c *ConnResponseWriter) WriteHeader(statusCode int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writeHeader(statusCode)
}

// Close closes network connection.
func (c *ConnResponseWriter) Close() error {
	return c.Conn.Close()
}

func (c *ConnResponseWriter) writeHeader(statusCode int) {
	if c.err != nil {
		return
	}
	if c.headersSent {
		return
	}
	st := http.StatusText(statusCode)
	if st != "" {
		st = " " + st
	}
	if _, err := io.WriteString(c.Conn, fmt.Sprintf("HTTP/1.1 %d%s\r\n", statusCode, st)); err != nil {
		c.err = err
		return
	}
	if err := c.header.Write(c.Conn); err != nil {
		c.err = err
		return
	}
	if _, err := io.WriteString(c.Conn, "\r\n"); err != nil {
		c.err = err
		return
	}
	c.headersSent = true
}
