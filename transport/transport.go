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
