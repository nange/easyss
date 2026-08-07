package proxy

import (
	"errors"
	"fmt"
	"io"
	"testing"

	"github.com/nange/easyss/v3/transport"
)

func TestClassifyFirstReadError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want error
	}{
		{
			name: "nil",
			err:  nil,
			want: nil,
		},
		{
			name: "ciphertext exceeds max maps to rejection",
			err:  fmt.Errorf("crypto: ciphertext exceeds max %d, got %d", 65552, 3940676),
			want: ErrServerRejectedHandshake,
		},
		{
			name: "zero-length ciphertext maps to rejection",
			err:  errors.New("crypto: zero-length ciphertext"),
			want: ErrServerRejectedHandshake,
		},
		{
			name: "decrypt failure maps to rejection",
			err:  fmt.Errorf("crypto: decrypt record: %w", errors.New("cipher: message authentication failed")),
			want: ErrServerRejectedHandshake,
		},
		{
			name: "transport rejection passes through",
			err:  &transport.HandshakeRejectedError{StatusCode: 408, Status: "408 Request Timeout"},
			want: &transport.HandshakeRejectedError{},
		},
		{
			name: "already-classified rejection passes through",
			err:  fmt.Errorf("wrapped: %w", ErrServerRejectedHandshake),
			want: ErrServerRejectedHandshake,
		},
		{
			name: "connection loss is not a rejection",
			err:  errors.New("crypto: read cipher_len: http2: client connection lost"),
			want: nil,
		},
		{
			name: "EOF is not a rejection",
			err:  io.EOF,
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyFirstReadError(tt.err)
			switch tt.want {
			case nil:
				if tt.err == nil {
					if got != nil {
						t.Fatalf("classifyFirstReadError(nil) = %v, want nil", got)
					}
					return
				}
				if got == nil || errors.Is(got, ErrServerRejectedHandshake) || transport.IsHandshakeRejected(got) {
					t.Fatalf("classifyFirstReadError(%v) = %v, want the original error unchanged", tt.err, got)
				}
				if got.Error() != tt.err.Error() {
					t.Fatalf("classifyFirstReadError(%v) = %v, want the original error unchanged", tt.err, got)
				}
			case ErrServerRejectedHandshake:
				if !errors.Is(got, ErrServerRejectedHandshake) {
					t.Fatalf("classifyFirstReadError(%v) = %v, want ErrServerRejectedHandshake", tt.err, got)
				}
			default:
				if !transport.IsHandshakeRejected(got) {
					t.Fatalf("classifyFirstReadError(%v) = %v, want HandshakeRejectedError", tt.err, got)
				}
			}
		})
	}
}

func TestIsTransientStreamError(t *testing.T) {
	transient := []error{
		ErrStreamIdleTimeout,
		ErrStreamReset,
		ErrServerRejectedHandshake,
		fmt.Errorf("wrapped: %w", ErrServerRejectedHandshake),
		&transport.HandshakeRejectedError{StatusCode: 408},
		errors.New("crypto: read cipher_len: http2: client connection lost"),
		errors.New("crypto: write record: http2: stream closed"),
		errors.New("write on closed connection: connection reset by peer"),
	}
	for _, err := range transient {
		if !isTransientStreamError(err) {
			t.Errorf("isTransientStreamError(%v) = false, want true", err)
		}
	}

	permanent := []error{
		errors.New("crypto: ciphertext exceeds max 65552, got 3940676"),
		fmt.Errorf("server rejected handshake"),
	}
	for _, err := range permanent {
		if isTransientStreamError(err) {
			t.Errorf("isTransientStreamError(%v) = true, want false", err)
		}
	}
	if isTransientStreamError(nil) {
		t.Error("isTransientStreamError(nil) = true, want false")
	}
}
