package transport

import (
	"context"
	"errors"
	"fmt"
	"io"
)

// HandshakeRejectedError reports that the server answered the bootstrap
// handshake with a non-200 status (e.g. 408 Request Timeout, 400 Bad
// Request), meaning the stream was rejected before any session records were
// exchanged. The client fails fast on the first read instead of misparsing
// the rejection body as encrypted records.
type HandshakeRejectedError struct {
	StatusCode int
	Status     string
}

func (e *HandshakeRejectedError) Error() string {
	if e.Status != "" {
		return fmt.Sprintf("handshake rejected: server returned HTTP %d %s", e.StatusCode, e.Status)
	}
	return fmt.Sprintf("handshake rejected: server returned HTTP %d", e.StatusCode)
}

// IsHandshakeRejected reports whether err indicates the server rejected the
// handshake with a non-200 status.
func IsHandshakeRejected(err error) bool {
	var e *HandshakeRejectedError
	return errors.As(err, &e)
}

type Stream interface {
	io.Reader
	io.Writer
	CloseWrite() error
	Close() error
}

type OpenRequest struct {
	Endpoint     string
	Salt         string
	HighPriority bool
}

type TransportStats struct {
	Conns                 int `json:"conns"`
	ActiveStreams         int `json:"active_streams"`
	PriorityActiveStreams int `json:"priority_active_streams"`
	BulkActiveStreams     int `json:"bulk_active_streams"`
	PriorityConns         int `json:"priority_conns"`
	BulkConns             int `json:"bulk_conns"`
}

type Transport interface {
	Open(ctx context.Context, req OpenRequest) (Stream, error)
	CloseIdle()
	Stats() TransportStats
	Close() error
}
