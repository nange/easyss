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

// Direction 标识会话的一侧：客户端到服务端或服务端到客户端。
// 每个方向拥有独立的密钥与 nonce 计数器。
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

// ErrHandshakeTimeout 报告在握手超时时间内未收到完整的 bootstrap 记录。
// 此时服务端返回 408 Request Timeout（镜像 nginx client_body_timeout 的行为）
// 而不是伪装 fallback 页面，这样记录只是延迟到达的合法客户端会收到干净的
// 拒绝，而不是把 HTML 误解析为会话记录。
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

// BootstrapWriter 返回流的首条记录（携带握手的 bootstrap 记录）的写入器。
// bootstrap 阶段始终在 c2s 密钥上使用 AES-256-GCM，因此调用方无法选择
// 不匹配的方法。
func (sk *StreamKeys) BootstrapWriter(w io.Writer) (*RecordWriter, error) {
	return sk.newRecordWriter(w, bootstrapPhase, DirC2S, protocol.MethodAES256GCM)
}

// NewWriter 返回给定方向的会话阶段记录写入器。
func (sk *StreamKeys) NewWriter(w io.Writer, dir Direction, method protocol.Method) (*RecordWriter, error) {
	return sk.newRecordWriter(w, sessionPhase, dir, method)
}

// NewReader 返回给定方向的会话阶段记录读取器。读取器与写入器连同各自的
// AAD、加密器和 nonce 计数器一起创建，三者永远不会不一致，且一个方向的
// 计数器只实例化一次（对同一方向调用两次 newEncryptor 会重启 nonce 计数器
// 并复用密钥流）。
func (sk *StreamKeys) NewReader(r io.Reader, dir Direction, method protocol.Method) (*DecryptedReader, error) {
	enc, counter, err := sk.newEncryptor(sessionPhase, dir, method)
	if err != nil {
		return nil, err
	}
	return NewDecryptedReader(r, sk.aad(dir, sessionPhase, method), enc, counter), nil
}

// NewRecordReader 是不带帧层的 NewReader，供自行解码记录的调用方使用
// （例如测试和 bootstrap 首条记录读取）。
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

// aad 构建附加认证数据，把记录绑定到本流的端点、salt、方向、阶段与方法。
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
	frames   []protocol.Frame // 先前记录留下的残余帧
	frameBuf []protocol.Frame // decodeFramesIntoBuf 的可复用后备数组
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

// decodeFramesIntoBuf 把解密的记录拆分为帧，复用 buf 作为后备数组。
// 帧的 payload 别名自 plaintext，其生命周期由调用方负责。
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

	// 首条记录可能携带不止握手本身（客户端会把首条 DATA/DATAGRAM 帧
	// 和一个 padding 帧合并进来）。
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
		// 读 goroutine 可能恰在定时器触发的同一瞬间完成：先排空带缓冲的结果，
		// 避免把一个完全有效（但较慢）的握手误判为超时。
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
