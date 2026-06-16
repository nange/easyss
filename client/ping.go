package client

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/crypto"
	"github.com/nange/easyss/v3/protocol"
	"github.com/nange/easyss/v3/transport"
)

func (c *Client) Ping(ctx context.Context) (time.Duration, error) {
	salt, err := crypto.GenerateSalt()
	if err != nil {
		return 0, fmt.Errorf("ping generate salt: %w", err)
	}

	saltB64 := base64.RawURLEncoding.EncodeToString(salt)

	req := transport.OpenRequest{
		Endpoint: config.EndpointPing,
		Salt:     saltB64,
	}

	start := time.Now()

	stream, err := c.transport.Open(ctx, req)
	if err != nil {
		return 0, fmt.Errorf("ping transport open: %w", err)
	}
	defer stream.Close() //nolint:errcheck

	sk, err := crypto.NewStreamKeys(c.masterKey, salt, config.EndpointPing)
	if err != nil {
		return 0, fmt.Errorf("ping stream keys: %w", err)
	}

	bootstrapEnc, bootstrapCounter, err := sk.Encryptor("c2s", "bootstrap", protocol.MethodAES256GCM)
	if err != nil {
		return 0, fmt.Errorf("ping bootstrap encryptor: %w", err)
	}
	aad := crypto.BuildAAD(config.EndpointPing, salt, "c2s", "bootstrap", protocol.MethodAES256GCM)
	rw := crypto.NewRecordWriter(stream, bootstrapEnc, bootstrapCounter, aad)

	handshake := protocol.Handshake{
		Version: protocol.Version3,
		Proto:   protocol.ProtoTCP,
		Method:  protocol.MethodFromString(c.cfg.DefaultServer().Method),
		Target:  "ping",
	}
	hsFrame := protocol.NewFrameHANDSHAKE(handshake)

	ts := make([]byte, 8)
	binary.BigEndian.PutUint64(ts, uint64(start.UnixNano()))
	dataFrame := protocol.NewFrameDATA(ts)

	plaintext := protocol.EncodeFrames([]protocol.Frame{hsFrame, dataFrame})
	if err := rw.WriteRecord(plaintext); err != nil {
		return 0, fmt.Errorf("ping write handshake+data: %w", err)
	}

	method := protocol.MethodFromString(c.cfg.DefaultServer().Method)
	aadS2C := crypto.BuildAAD(config.EndpointPing, salt, "s2c", "session", method)
	s2cEnc, s2cCounter, err := sk.Encryptor("s2c", "session", method)
	if err != nil {
		return 0, fmt.Errorf("ping s2c encryptor: %w", err)
	}
	dr := crypto.NewDecryptedReader(stream, aadS2C, s2cEnc, s2cCounter)

	frame, err := dr.ReadFrame()
	if err != nil {
		if errors.Is(err, io.EOF) {
			return 0, fmt.Errorf("ping server closed connection")
		}
		return 0, fmt.Errorf("ping read reply: %w", err)
	}

	if frame.Type == protocol.FrameRST {
		return 0, fmt.Errorf("ping rejected by server")
	}

	if frame.Type != protocol.FrameDATA {
		return 0, fmt.Errorf("ping expected DATA frame, got %d", frame.Type)
	}

	return time.Since(start), nil
}
