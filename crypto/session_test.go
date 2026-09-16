package crypto

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// silentReader 永不投递数据，用于模拟停滞的握手。
type silentReader struct{}

func (silentReader) Read([]byte) (int, error) { return 0, nil }

func TestReadFirstRecordWithTimeout_ReturnsErrHandshakeTimeout(t *testing.T) {
	masterKey, err := DeriveMasterKey("test-password")
	require.NoError(t, err)
	salt, err := GenerateSalt()
	require.NoError(t, err)

	sk, err := NewStreamKeys(masterKey, salt, "/v3/tcp")
	require.NoError(t, err)

	start := time.Now()
	_, err = sk.ReadFirstRecordWithTimeout(context.Background(), silentReader{}, 100*time.Millisecond)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrHandshakeTimeout),
		"expected error to wrap ErrHandshakeTimeout, got: %v", err)
	require.True(t, time.Since(start) < 2*time.Second, "handshake read should time out quickly")
}

func TestReadFirstRecordWithTimeout_ReturnsReaderError(t *testing.T) {
	masterKey, err := DeriveMasterKey("test-password")
	require.NoError(t, err)
	salt, err := GenerateSalt()
	require.NoError(t, err)

	sk, err := NewStreamKeys(masterKey, salt, "/v3/tcp")
	require.NoError(t, err)

	// 立即 EOF 属于读取失败，而非超时。
	_, err = sk.ReadFirstRecordWithTimeout(context.Background(), &eofReader{}, time.Second)
	require.Error(t, err)
	require.False(t, errors.Is(err, ErrHandshakeTimeout),
		"EOF should not be classified as a handshake timeout, got: %v", err)
}

type eofReader struct{}

func (eofReader) Read([]byte) (int, error) { return 0, io.EOF }
