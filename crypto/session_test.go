package crypto

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// silentReader never delivers data, simulating a stalled handshake.
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

	// An immediate EOF is a read failure, not a timeout.
	_, err = sk.ReadFirstRecordWithTimeout(context.Background(), &eofReader{}, time.Second)
	require.Error(t, err)
	require.False(t, errors.Is(err, ErrHandshakeTimeout),
		"EOF should not be classified as a handshake timeout, got: %v", err)
}

type eofReader struct{}

func (eofReader) Read([]byte) (int, error) { return 0, io.EOF }
