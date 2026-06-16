package crypto

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/nange/easyss/v3/protocol"
)

const (
	bootstrapPhase = "bootstrap"
	sessionPhase   = "session"
)

type FirstRecord struct {
	Handshake protocol.Handshake
	Leftover  []protocol.Frame
}

type StreamKeys struct {
	masterKey []byte
	salt      []byte
	Endpoint  string

	bootstrapEncryptor   Encryptor
	bootstrapNoncePrefix [4]byte

	sessionKeys SessionKeys
}

func NewStreamKeys(masterKey, salt []byte, endpoint string) (*StreamKeys, error) {
	if len(masterKey) != keySize {
		return nil, fmt.Errorf("crypto: master key must be %d bytes", keySize)
	}
	if len(salt) != saltSize {
		return nil, fmt.Errorf("crypto: salt must be %d bytes", saltSize)
	}

	bk, err := DeriveBootstrapKeys(masterKey, salt)
	if err != nil {
		return nil, fmt.Errorf("crypto: derive bootstrap keys: %w", err)
	}

	bootstrapEnc, err := NewAES256GCM(bk.Key[:])
	if err != nil {
		return nil, fmt.Errorf("crypto: new bootstrap encryptor: %w", err)
	}

	sk, err := DeriveSessionKeys(masterKey, salt)
	if err != nil {
		return nil, fmt.Errorf("crypto: derive session keys: %w", err)
	}

	return &StreamKeys{
		masterKey:            masterKey,
		salt:                 salt,
		Endpoint:             endpoint,
		bootstrapEncryptor:   bootstrapEnc,
		bootstrapNoncePrefix: bk.NoncePrefix,
		sessionKeys:          sk,
	}, nil
}

func (sk *StreamKeys) Salt() []byte {
	return sk.salt
}

func (sk *StreamKeys) Encryptor(direction, phase string, method protocol.Method) (Encryptor, *CounterNonce, error) {
	var key [32]byte
	var noncePrefix [4]byte

	switch phase {
	case bootstrapPhase:
		return sk.bootstrapEncryptor, NewCounterNonce(sk.bootstrapNoncePrefix), nil
	case sessionPhase:
		switch direction {
		case "c2s":
			key = sk.sessionKeys.C2SKey
			noncePrefix = sk.sessionKeys.C2SNoncePrefix
		case "s2c":
			key = sk.sessionKeys.S2CKey
			noncePrefix = sk.sessionKeys.S2CNoncePrefix
		default:
			return nil, nil, fmt.Errorf("crypto: invalid direction %s", direction)
		}
	default:
		return nil, nil, fmt.Errorf("crypto: invalid phase %s", phase)
	}

	var enc Encryptor
	var err error
	switch method {
	case protocol.MethodAES256GCM:
		enc, err = NewAES256GCM(key[:])
	case protocol.MethodChaCha20Poly1305:
		enc, err = NewChaCha20Poly1305(key[:])
	default:
		return nil, nil, fmt.Errorf("crypto: unsupported method %s", method)
	}
	if err != nil {
		return nil, nil, err
	}

	return enc, NewCounterNonce(noncePrefix), nil
}

func BuildAAD(endpoint string, salt []byte, direction, phase string, method protocol.Method) []byte {
	prefix := "easyss-v3" + endpoint
	b := make([]byte, 0, len(prefix)+len(salt)+len(direction)+len(phase)+len(method.String())+4)
	b = append(b, prefix...)
	b = append(b, salt...)
	b = append(b, '/')
	b = append(b, direction...)
	b = append(b, '/')
	b = append(b, phase...)
	b = append(b, '/')
	b = append(b, method.String()...)
	return b
}

type DecryptedReader struct {
	reader *RecordReader
	frames []protocol.Frame // leftover frames from previous records
}

func NewDecryptedReader(r io.Reader, aad []byte, encryptor Encryptor, counter *CounterNonce) *DecryptedReader {
	rr := NewRecordReader(r, encryptor, counter, aad)
	return &DecryptedReader{
		reader: rr,
	}
}

func (dr *DecryptedReader) SetLeftoverFrames(frames []protocol.Frame) {
	dr.frames = frames
}

func (dr *DecryptedReader) ReadFrame() (protocol.Frame, error) {
	if len(dr.frames) > 0 {
		f := dr.frames[0]
		dr.frames = dr.frames[1:]
		return f, nil
	}

	plaintext, err := dr.reader.ReadRecord()
	if err != nil {
		return protocol.Frame{}, err
	}

	frames, err := decodeFramesFromPlaintext(plaintext)
	if err != nil {
		return protocol.Frame{}, err
	}
	if len(frames) == 0 {
		return protocol.Frame{}, io.ErrUnexpectedEOF
	}
	dr.frames = frames[1:]
	return frames[0], nil
}

func decodeFramesFromPlaintext(plaintext []byte) ([]protocol.Frame, error) {
	if len(plaintext) < protocol.FrameHeaderSize {
		return nil, io.ErrUnexpectedEOF
	}

	frames := make([]protocol.Frame, 0, 4)
	for len(plaintext) > 0 {
		f, err := decodeFrame(plaintext)
		if err != nil {
			return nil, err
		}
		frames = append(frames, f)
		plaintext = plaintext[f.EncodedLen():]
	}

	return frames, nil
}

func decodeFrame(data []byte) (protocol.Frame, error) {
	if len(data) < protocol.FrameHeaderSize {
		return protocol.Frame{}, io.ErrUnexpectedEOF
	}
	ftype := protocol.FrameType(data[0])
	length := uint16(data[1])<<8 | uint16(data[2])
	payload := data[3:]

	if int(length) > len(payload) {
		return protocol.Frame{}, io.ErrUnexpectedEOF
	}

	return protocol.Frame{
		Type:    ftype,
		Length:  length,
		Payload: payload[:length],
	}, nil
}

func (sk *StreamKeys) ReadFirstRecord(src io.Reader) (FirstRecord, error) {
	bootstrapEnc, bootstrapCounter, err := sk.Encryptor("c2s", bootstrapPhase, protocol.MethodAES256GCM)
	if err != nil {
		return FirstRecord{}, fmt.Errorf("crypto: read first record: %w", err)
	}
	aad := BuildAAD(sk.Endpoint, sk.salt, "c2s", bootstrapPhase, protocol.MethodAES256GCM)

	rr := NewRecordReader(src, bootstrapEnc, bootstrapCounter, aad)
	plaintext, err := rr.ReadRecord()
	if err != nil {
		return FirstRecord{}, fmt.Errorf("crypto: read first record: %w", err)
	}

	reader := &rawFrameReader{data: plaintext}
	frame, err := protocol.ReadFrame(reader)
	if err != nil {
		return FirstRecord{}, fmt.Errorf("crypto: read first frame: %w", err)
	}

	if frame.Type != protocol.FrameHANDSHAKE {
		return FirstRecord{}, fmt.Errorf("crypto: expected HANDSHAKE frame, got %d", frame.Type)
	}

	handshake, err := protocol.DecodeHandshake(frame.Payload)
	if err != nil {
		return FirstRecord{}, fmt.Errorf("crypto: decode handshake: %w", err)
	}

	leftoverBytes := reader.data[reader.offset:]
	leftover, err := decodeFramesFromPlaintextAllowEmpty(leftoverBytes)
	if err != nil {
		return FirstRecord{}, fmt.Errorf("crypto: decode leftover frames: %w", err)
	}

	return FirstRecord{
		Handshake: handshake,
		Leftover:  leftover,
	}, nil
}

func decodeFramesFromPlaintextAllowEmpty(plaintext []byte) ([]protocol.Frame, error) {
	if len(plaintext) == 0 {
		return nil, nil
	}
	return decodeFramesFromPlaintext(plaintext)
}

func (sk *StreamKeys) ReadFirstRecordWithTimeout(ctx context.Context, src io.Reader, timeout time.Duration) (FirstRecord, error) {
	type result struct {
		fr  FirstRecord
		err error
	}
	ch := make(chan result, 1)
	go func() {
		fr, err := sk.ReadFirstRecord(src)
		ch <- result{fr, err}
	}()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		closeReader(src)
		return FirstRecord{}, ctx.Err()
	case <-timer.C:
		closeReader(src)
		return FirstRecord{}, fmt.Errorf("crypto: bootstrap handshake timeout after %v", timeout)
	case res := <-ch:
		return res.fr, res.err
	}
}

func closeReader(r io.Reader) {
	if closer, ok := r.(io.Closer); ok {
		closer.Close() //nolint:errcheck
	}
}

type rawFrameReader struct {
	data   []byte
	offset int
}

func (r *rawFrameReader) Read(p []byte) (int, error) {
	if r.offset >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.offset:])
	r.offset += n
	return n, nil
}
