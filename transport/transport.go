package transport

import (
	"context"
	"io"
)

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
	ConnCount    int
	ActiveStream int
}

type Transport interface {
	Open(ctx context.Context, req OpenRequest) (Stream, error)
	CloseIdle()
	Stats() TransportStats
	Close() error
}
