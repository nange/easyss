package proxy

import (
	"io"
	"net"
	"testing"
	"time"
)

// tcpPair dials a fresh local TCP pair (client side + accepted server side)
// and returns both ends.
func tcpPair(t *testing.T) (client, server net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close() //nolint:errcheck

	accepted := make(chan net.Conn, 1)
	go func() {
		c, aErr := ln.Accept()
		if aErr != nil {
			return
		}
		accepted <- c
	}()

	client, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { client.Close() }) //nolint:errcheck

	select {
	case server = <-accepted:
	case <-time.After(2 * time.Second):
		client.Close() //nolint:errcheck
		t.Fatal("accept timed out")
	}
	t.Cleanup(func() { server.Close() }) //nolint:errcheck
	return client, server
}

// connClosed reports whether the connection has been closed: a read on a
// closed TCP connection returns an error (possibly after the FIN/EOF of a
// half-close, which also proves no data keeps flowing).
func connClosed(t *testing.T, conn net.Conn) bool {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 1)
	_, err := conn.Read(buf)
	return err != nil
}

// TestRelayTCPIdleTimeoutClosesBoth verifies that relayTCP honors its idle
// timeout argument: a silent pair must be torn down (both connections closed)
// after the given idle, so the copy goroutines cannot linger forever.
func TestRelayTCPIdleTimeoutClosesBoth(t *testing.T) {
	client, server := tcpPair(t)

	const idle = 100 * time.Millisecond
	start := time.Now()
	relayTCP(client, server, idle)
	if elapsed := time.Since(start); elapsed < idle {
		t.Fatalf("relay returned after %v, want >= %v idle", elapsed, idle)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("relay took %v, want ~%v", elapsed, idle)
	}
	if !connClosed(t, client) {
		t.Error("client connection still open after idle timeout")
	}
	if !connClosed(t, server) {
		t.Error("server connection still open after idle timeout")
	}
}

// TestRelayTCPHalfCloseAndCompletion verifies the half-close semantics of the
// direct relay with a faithful topology: two separate TCP pairs simulate the
// local application <-> proxy leg and the proxy <-> remote leg, with the
// relay bridging the proxy-side sockets. Each socket has exactly one reader
// and one writer, like production. A FIN on one leg is propagated to the
// other via CloseWrite while the reverse direction keeps flowing, and the
// relay returns only after both directions completed (both proxy-side
// sockets closed).
func TestRelayTCPHalfCloseAndCompletion(t *testing.T) {
	app, proxyC := tcpPair(t)     // local application <-> proxy
	proxyRC, remote := tcpPair(t) // proxy <-> remote server

	done := make(chan struct{})
	go func() {
		relayTCP(proxyRC, proxyC, time.Minute) // same orientation as TCPHandle
		close(done)
	}()

	// The application sends its payload and half-closes its write side:
	// the relay must forward the FIN to the remote (CloseWrite) while the
	// remote->application direction stays alive.
	if _, err := app.Write([]byte("hello")); err != nil {
		t.Fatalf("app write: %v", err)
	}
	if err := app.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatalf("app CloseWrite: %v", err)
	}

	buf := make([]byte, 5)
	if _, err := io.ReadFull(remote, buf); err != nil {
		t.Fatalf("remote read payload: %v", err)
	}
	if string(buf) != "hello" {
		t.Fatalf("remote got %q, want %q", buf, "hello")
	}
	// The application FIN must have reached the remote: next read is EOF.
	if _, err := remote.Read(buf); err != io.EOF {
		t.Fatalf("remote read after app FIN = %v, want io.EOF", err)
	}

	// The remote answers and half-closes; the relay must deliver the
	// payload and the FIN back to the application.
	if _, err := remote.Write([]byte("world")); err != nil {
		t.Fatalf("remote write: %v", err)
	}
	if err := remote.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatalf("remote CloseWrite: %v", err)
	}
	if _, err := io.ReadFull(app, buf); err != nil {
		t.Fatalf("app read payload: %v", err)
	}
	if string(buf) != "world" {
		t.Fatalf("app got %q, want %q", buf, "world")
	}
	// The remote FIN must have reached the application.
	if _, err := app.Read(buf); err != io.EOF {
		t.Fatalf("app read after remote FIN = %v, want io.EOF", err)
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("relay did not return after both directions completed")
	}
	// The relay closed both proxy-side sockets; the app/remote ends saw
	// their FINs above and are now fully closed too.
	if !connClosed(t, app) {
		t.Error("app connection still open after relay completed")
	}
	if !connClosed(t, remote) {
		t.Error("remote connection still open after relay completed")
	}
}
