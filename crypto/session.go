package crypto

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/nange/easyss/v3/protocol"
)

const (
	bootstrapPhase = "bootstrap"
	sessionPhase   = "session"
)

// Direction identifies one side of a session: client-to-server or
// server-to-client. Each direction has its own key and nonce counter.
type Direction uint8

const (
	DirC2S Direction = 1
	DirS2C Direction = 2
)

func (d Direction) String() string {
	switch d {
	case DirC2S:
		return "c2s"
	case DirS2C:
		return "s2c"
	default:
		return "unknown"
	}
}

// ErrHandshakeTimeout reports that a complete bootstrap record was not
// received within the handshake timeout. The server responds with 408
// Request Timeout (mirroring nginx client_body_timeout behavior) instead of a
// camouflaged fallback page, so a legit client with a merely-delayed record
// gets a clean rejection instead of misparsing HTML as session records.
var ErrHandshakeTimeout = errors.New("crypto: bootstrap handshake timeout")

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

// BootstrapWriter returns the record writer for a stream's first record (the
// bootstrap record carrying the handshake). The bootstrap phase always uses
// AES-256-GCM on the c2s key, so the caller cannot select a mismatched method.
func (sk *StreamKeys) BootstrapWriter(w io.Writer) (*RecordWriter, error) {
	return sk.newRecordWriter(w, bootstrapPhase, DirC2S, protocol.MethodAES256GCM)
}

// NewWriter returns a session-phase record writer for the given direction.
func (sk *StreamKeys) NewWriter(w io.Writer, dir Direction, method protocol.Method) (*RecordWriter, error) {
	return sk.newRecordWriter(w, sessionPhase, dir, method)
}

// NewReader returns a session-phase record reader for the given direction.
// Reader and writer are created together with their AAD, encryptor and nonce
// counter, so the three can never disagree and a direction's counter is
// instantiated exactly once (calling newEncryptor twice for one direction
// would restart the nonce counter and reuse keystream).
func (sk *StreamKeys) NewReader(r io.Reader, dir Direction, method protocol.Method) (*DecryptedReader, error) {
	enc, counter, err := sk.newEncryptor(sessionPhase, dir, method)
	if err != nil {
		return nil, err
	}
	return NewDecryptedReader(r, sk.aad(dir, sessionPhase, method), enc, counter), nil
}

// NewRecordReader is NewReader without the frame layer, for callers that
// decode records themselves (e.g. tests and the bootstrap first-record read).
func (sk *StreamKeys) NewRecordReader(r io.Reader, dir Direction, method protocol.Method) (*RecordReader, error) {
	enc, counter, err := sk.newEncryptor(sessionPhase, dir, method)
	if err != nil {
		return nil, err
	}
	return NewRecordReader(r, enc, counter, sk.aad(dir, sessionPhase, method)), nil
}

func (sk *StreamKeys) newRecordWriter(w io.Writer, phase string, dir Direction, method protocol.Method) (*RecordWriter, error) {
	enc, counter, err := sk.newEncryptor(phase, dir, method)
	if err != nil {
		return nil, err
	}
	return NewRecordWriter(w, enc, counter, sk.aad(dir, phase, method)), nil
}

// aad builds the additional authenticated data binding a record to this
// stream's endpoint, salt, direction, phase and method.
func (sk *StreamKeys) aad(dir Direction, phase string, method protocol.Method) []byte {
	return buildAAD(sk.Endpoint, sk.salt, dir.String(), phase, method)
}

func (sk *StreamKeys) newEncryptor(phase string, dir Direction, method protocol.Method) (Encryptor, *CounterNonce, error) {
	var key [32]byte
	var noncePrefix [4]byte

	switch phase {
	case bootstrapPhase:
		return sk.bootstrapEncryptor, NewCounterNonce(sk.bootstrapNoncePrefix), nil
	case sessionPhase:
		switch dir {
		case DirC2S:
			key = sk.sessionKeys.C2SKey
			noncePrefix = sk.sessionKeys.C2SNoncePrefix
		case DirS2C:
			key = sk.sessionKeys.S2CKey
			noncePrefix = sk.sessionKeys.S2CNoncePrefix
		default:
			return nil, nil, fmt.Errorf("crypto: invalid direction %s", dir)
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

func buildAAD(endpoint string, salt []byte, direction, phase string, method protocol.Method) []byte {
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
	reader   *RecordReader
	frames   []protocol.Frame // leftover frames from previous records
	frameBuf []protocol.Frame // reusable backing array for decodeFramesIntoBuf
}

func NewDecryptedReader(r io.Reader, aad []byte, encryptor Encryptor, counter *CounterNonce) *DecryptedReader {
	rr := NewRecordReader(r, encryptor, counter, aad)
	return &DecryptedReader{
		reader:   rr,
		frameBuf: make([]protocol.Frame, 0, 8),
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

	frames, err := decodeFramesIntoBuf(plaintext, dr.frameBuf[:0])
	if err != nil {
		return protocol.Frame{}, err
	}
	if len(frames) == 0 {
		return protocol.Frame{}, io.ErrUnexpectedEOF
	}
	dr.frames = frames[1:]
	return frames[0], nil
}

// decodeFramesIntoBuf splits a decrypted record into frames, reusing buf as
// the backing array. Frame payloads alias plaintext, whose lifetime is the
// caller's.
func decodeFramesIntoBuf(plaintext []byte, buf []protocol.Frame) ([]protocol.Frame, error) {
	frames := buf[:0]
	for len(plaintext) > 0 {
		f, n, err := protocol.DecodeFrame(plaintext)
		if err != nil {
			return nil, err
		}
		frames = append(frames, f)
		plaintext = plaintext[n:]
	}
	return frames, nil
}

func (sk *StreamKeys) ReadFirstRecord(src io.Reader) (FirstRecord, error) {
	bootstrapEnc, bootstrapCounter, err := sk.newEncryptor(bootstrapPhase, DirC2S, protocol.MethodAES256GCM)
	if err != nil {
		return FirstRecord{}, fmt.Errorf("crypto: read first record: %w", err)
	}

	rr := NewRecordReader(src, bootstrapEnc, bootstrapCounter, sk.aad(DirC2S, bootstrapPhase, protocol.MethodAES256GCM))
	plaintext, err := rr.ReadRecord()
	if err != nil {
		return FirstRecord{}, fmt.Errorf("crypto: read first record: %w", err)
	}

	frame, n, err := protocol.DecodeFrame(plaintext)
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

	// The first record may carry more than the handshake (the client merges
	// the first DATA/DATAGRAM and a padding frame into it).
	leftover, err := decodeFramesIntoBuf(plaintext[n:], nil)
	if err != nil {
		return FirstRecord{}, fmt.Errorf("crypto: decode leftover frames: %w", err)
	}

	return FirstRecord{
		Handshake: handshake,
		Leftover:  leftover,
	}, nil
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
		// The read goroutine may have finished in the same instant the timer
		// fired: draining the buffered result first avoids misjudging a
		// perfectly valid (but slow) handshake as a timeout.
		select {
		case res := <-ch:
			return res.fr, res.err
		default:
		}
		closeReader(src)
		return FirstRecord{}, fmt.Errorf("%w after %v", ErrHandshakeTimeout, timeout)
	case res := <-ch:
		return res.fr, res.err
	}
}

func closeReader(r io.Reader) {
	if closer, ok := r.(io.Closer); ok {
		closer.Close() //nolint:errcheck
	}
}
