package cipherstream

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type testServer struct {
	listener net.Listener
}

func (t *testServer) serve(port string) {
	lis, err := net.Listen("tcp", ":"+port)
	if err != nil {
		panic(err)
	}
	t.listener = lis
}

func (t *testServer) accept() (net.Conn, error) {
	return t.listener.Accept()
}

func (t *testServer) close() {
	if t.listener != nil {
		t.listener.Close()
	}
}

func TestCipherStream(t *testing.T) {
	server := &testServer{}
	defer server.close()
	go server.serve("7878")

	time.Sleep(2 * time.Second)
	conn, err := net.Dial("tcp", "127.0.0.1:7878")
	require.Nil(t, err)
	defer conn.Close()

	cipherConn, err := New(conn, "test-pass", "aes-256-gcm", FrameTypeData, FlagTCP)
	require.Nil(t, err)

	_, err = cipherConn.Write([]byte("Hello world!"))
	require.Nil(t, err)

	serverConn, err := server.accept()
	require.Nil(t, err)
	defer serverConn.Close()

	serverCipherConn, err := New(serverConn, "test-pass", "aes-256-gcm", FrameTypeData, FlagTCP)
	require.Nil(t, err)

	b := make([]byte, 64)
	nr, err := serverCipherConn.Read(b)
	require.Nil(t, err)
	require.Equal(t, 12, nr)
	require.Equal(t, "Hello world!", string(b[:nr]))

}
