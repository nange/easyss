package transport

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"
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

// SlotDrainingStream is implemented by streams whose underlying connection
// slot is due for eviction: expiring (the connection exceeded its lifetime or
// bytes limit) or degraded (confirmed persistently low throughput). The proxy
// layer asserts this optional interface to drain idle streams early (see
// relay.BidirectionalWithDrain), so lingering keep-alive and half-closed
// connections cannot postpone the slot's rotation/retirement until the full
// relay idle timeout. Streams that do not implement it simply never drain.
type SlotDrainingStream interface {
	SlotDraining() bool
}

type OpenRequest struct {
	Endpoint     string
	Salt         string
	HighPriority bool
	// Target is the stream's original destination as "host:port" (domain
	// or IP). It never participates in scheduling — it is carried so the
	// transport can attribute a slot-growth event to the request that
	// triggered it (see TransportStats.GrowEvents).
	Target string
}

type TransportStats struct {
	Conns                 int `json:"conns"`
	ActiveStreams         int `json:"active_streams"`
	PriorityActiveStreams int `json:"priority_active_streams"`
	BulkActiveStreams     int `json:"bulk_active_streams"`
	PriorityConns         int `json:"priority_conns"`
	BulkConns             int `json:"bulk_conns"`
	// PriorityConnsStatus is a compact per-connection status summary of the
	// priority pool, e.g. "[0:3:degraded, 1:2:expiring, 2:1:active]". Each
	// element is "<index>:<active streams>:<status>" where indices are
	// consecutive from 0 (ordered by stable connection identity) and status
	// is one of idle/active/heavy/degraded/expiring, with multiple flags
	// joined by "+". "idle" marks a healthy connection hosting no streams
	// (a warm connection), so a pool grown by a past burst is
	// distinguishable from active traffic. The bulk pool renders the same
	// way into BulkConnsStatus.
	PriorityConnsStatus string `json:"priority_conns_status,omitempty"`
	BulkConnsStatus     string `json:"bulk_conns_status,omitempty"`
	// GrowEvents lists the most recent slot-growth events (new connections
	// activated by the lazy-expansion scheduler), newest first, bounded to
	// a small ring (see HTTP2Transport.recordGrowEvent). Each event records
	// the pool that grew, the live slot count after growth, and the
	// endpoint/target of the request that triggered the growth, so a
	// sudden connection-count jump can be attributed to the traffic that
	// caused it.
	GrowEvents []GrowEvent `json:"recent_grow_events,omitempty"`
}

// GrowEvent is one slot-growth (new live connection) occurrence: which
// pool grew, the live slot count after growth, and the request that
// triggered it (its protocol endpoint and target host:port).
type GrowEvent struct {
	Time     time.Time `json:"time"`
	Pool     string    `json:"pool"` // "priority" or "bulk"
	Live     int       `json:"live"` // live slot count after growth
	Endpoint string    `json:"endpoint"`
	Target   string    `json:"target"`
}

type Transport interface {
	Open(ctx context.Context, req OpenRequest) (Stream, error)
	CloseIdle()
	Stats() TransportStats
	Close() error
}
