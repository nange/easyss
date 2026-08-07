package http2

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"

	sharedconfig "github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/transport"
)

func TestUTLSDialUsesHTTP2(t *testing.T) {
	protoCh := make(chan string, 1)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		protoCh <- r.Proto
		w.WriteHeader(http.StatusOK)
	}))
	srv.EnableHTTP2 = true
	srv.Config.Protocols = &http.Protocols{}
	srv.Config.Protocols.SetHTTP2(true)
	srv.StartTLS()
	t.Cleanup(srv.Close)

	slot := newSlot(&utls.Config{
		InsecureSkipVerify: true,
		NextProtos:         sharedconfig.NextProtos,
	}, time.Second, nil)
	t.Cleanup(slot.t.CloseIdleConnections)

	req, err := http.NewRequest(http.MethodPost, srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := slot.t.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	if got := <-protoCh; got != "HTTP/2.0" {
		t.Fatalf("server got %s, want HTTP/2.0", got)
	}
}

// TestHTTP2Transport_Non200StatusIsRejected verifies that a handshake
// answered with a non-200 status (e.g. 408 Request Timeout) fails fast with a
// HandshakeRejectedError instead of exposing the rejection body to the record
// reader.
func TestHTTP2Transport_Non200StatusIsRejected(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusRequestTimeout)
	}))
	srv.EnableHTTP2 = true
	srv.Config.Protocols = &http.Protocols{}
	srv.Config.Protocols.SetHTTP2(true)
	srv.StartTLS()
	t.Cleanup(srv.Close)

	tr, err := New(Config{
		ServerURL: srv.URL,
		TLSConfig: &utls.Config{
			InsecureSkipVerify: true,
			NextProtos:         sharedconfig.NextProtos,
		},
		Timeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tr.Close() })

	stream, err := tr.Open(context.Background(), transport.OpenRequest{
		Endpoint:     sharedconfig.EndpointTCP,
		Salt:         "dGVzdHNhbHR0ZXN0c2FsdA",
		HighPriority: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close() //nolint:errcheck

	buf := make([]byte, 16)
	_, err = stream.Read(buf)
	if err == nil {
		t.Fatal("expected a rejection error, got nil")
	}
	if !transport.IsHandshakeRejected(err) {
		t.Fatalf("expected HandshakeRejectedError, got: %v", err)
	}
}

// TestHTTP2Transport_200StatusReadsBody verifies that a 200 response is
// surfaced as a normal readable body.
func TestHTTP2Transport_200StatusReadsBody(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("hello"))
	}))
	srv.EnableHTTP2 = true
	srv.Config.Protocols = &http.Protocols{}
	srv.Config.Protocols.SetHTTP2(true)
	srv.StartTLS()
	t.Cleanup(srv.Close)

	tr, err := New(Config{
		ServerURL: srv.URL,
		TLSConfig: &utls.Config{
			InsecureSkipVerify: true,
			NextProtos:         sharedconfig.NextProtos,
		},
		Timeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tr.Close() })

	stream, err := tr.Open(context.Background(), transport.OpenRequest{
		Endpoint:     sharedconfig.EndpointTCP,
		Salt:         "dGVzdHNhbHR0ZXN0c2FsdA",
		HighPriority: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close() //nolint:errcheck

	body, err := io.ReadAll(stream)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "hello" {
		t.Fatalf("got %q, want %q", body, "hello")
	}
}
