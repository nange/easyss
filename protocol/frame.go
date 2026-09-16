package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"

	"github.com/nange/easyss/v3/config"
)

type FrameType uint8

const (
	FrameDATA      FrameType = 0x0
	FrameDATAGRAM  FrameType = 0x1
	FrameFIN       FrameType = 0x2
	FrameRST       FrameType = 0x3
	FramePADDING   FrameType = 0x4
	FrameCOVER     FrameType = 0x5
	FrameHANDSHAKE FrameType = 0x6
)

const (
	FrameHeaderSize = 3
)

const (
	Version3 = 3
)

type Proto uint8

const (
	ProtoTCP  Proto = 1
	ProtoUDP  Proto = 2
	ProtoICMP Proto = 3
)

func (p Proto) String() string {
	switch p {
	case ProtoTCP:
		return "tcp"
	case ProtoUDP:
		return "udp"
	case ProtoICMP:
		return "icmp"
	default:
		return "unknown"
	}
}

type Method uint8

const (
	MethodAES256GCM        Method = 1
	MethodChaCha20Poly1305 Method = 2
)

func MethodFromString(s string) Method {
	switch s {
	case "aes-256-gcm":
		return MethodAES256GCM
	case "chacha20-poly1305":
		return MethodChaCha20Poly1305
	default:
		return 0
	}
}

func (m Method) String() string {
	switch m {
	case MethodAES256GCM:
		return "aes-256-gcm"
	case MethodChaCha20Poly1305:
		return "chacha20-poly1305"
	default:
		return "unknown"
	}
}

const (
	MaxUDPDataSize     = 65507
	MaxPlainRecordSize = 64 * 1024
	MaxCipherLenSize   = 3
)

type Handshake struct {
	Version uint8
	Proto   Proto
	Method  Method
	Target  string
}

func (h Handshake) Encode() []byte {
	targetLen := len(h.Target)
	buf := make([]byte, 3+targetLen)
	buf[0] = h.Version
	buf[1] = byte(h.Proto)
	buf[2] = byte(h.Method)
	copy(buf[3:], h.Target)
	return buf
}

func DecodeHandshake(data []byte) (Handshake, error) {
	if len(data) < 3 {
		return Handshake{}, errors.New("protocol: handshake too short")
	}
	h := Handshake{
		Version: data[0],
		Proto:   Proto(data[1]),
		Method:  Method(data[2]),
		Target:  string(data[3:]),
	}
	if h.Version != Version3 {
		return Handshake{}, fmt.Errorf("protocol: unsupported version %d", h.Version)
	}
	return h, nil
}

func (h Handshake) MatchesEndpoint(endpoint string) bool {
	switch h.Proto {
	case ProtoTCP:
		return endpoint == config.EndpointTCP
	case ProtoUDP:
		return endpoint == config.EndpointUDP
	case ProtoICMP:
		return endpoint == config.EndpointICMP
	default:
		return false
	}
}

type Frame struct {
	Type    FrameType
	Length  uint16
	Payload []byte
}

func (f Frame) EncodedLen() int {
	return FrameHeaderSize + int(f.Length)
}

// DecodeFrame 从 data 头部解码一个帧。它是记录层的非流式对应物：解密的
// CryptoRecord 在内存中切分，因此不涉及 io.Reader。返回帧、其占用的字节数
// 以及错误。帧的 payload 别名自 data，其生命周期由调用方负责。
func DecodeFrame(data []byte) (Frame, int, error) {
	if len(data) < FrameHeaderSize {
		return Frame{}, 0, io.ErrUnexpectedEOF
	}
	ftype := FrameType(data[0])
	length := int(binary.BigEndian.Uint16(data[1:3]))
	encoded := FrameHeaderSize + length
	if encoded > len(data) {
		return Frame{}, 0, io.ErrUnexpectedEOF
	}

	f := Frame{Type: ftype, Length: uint16(length)}
	if length > 0 {
		f.Payload = data[FrameHeaderSize:encoded]
	}
	return f, encoded, nil
}

// NewFrame 构建给定类型的帧，并复制 payload，使调用方可以复用其缓冲区
// （shaper 交出的是 bytespool 缓冲区）。Length 始终由 payload 推导，
// 因此线上的头部永远不可能与随后写入的字节不一致。
func NewFrame(typ FrameType, payload []byte) Frame {
	return NewFrameWithPayload(typ, append([]byte(nil), payload...))
}

// NewFrameWithPayload 包装现有 payload 缓冲区而不复制，供持有池化缓冲区
// （cover 流量）的调用方使用：必须原样交给 shaper，以便归还池中。
func NewFrameWithPayload(typ FrameType, payload []byte) Frame {
	checkPayloadLen(payload)
	return Frame{
		Type:    typ,
		Length:  uint16(len(payload)),
		Payload: payload,
	}
}

// NewZeroFrame 构建给定类型的帧，payload 为 length 字节的零值缓冲区，
// 供随后再填充缓冲区的调用方使用（padding）。
func NewZeroFrame(typ FrameType, length uint16) Frame {
	return Frame{
		Type:    typ,
		Length:  length,
		Payload: make([]byte, length),
	}
}

func NewFrameDATA(data []byte) Frame {
	return NewFrame(FrameDATA, data)
}

func NewFrameDATAGRAM(data []byte) Frame {
	return NewFrame(FrameDATAGRAM, data)
}

func NewFrameFIN() Frame {
	return Frame{Type: FrameFIN}
}

func NewFrameRST() Frame {
	return Frame{Type: FrameRST}
}

func NewFramePADDING(length uint16) Frame {
	return NewZeroFrame(FramePADDING, length)
}

func NewFrameHANDSHAKE(h Handshake) Frame {
	return NewFrame(FrameHANDSHAKE, h.Encode())
}

func checkPayloadLen(payload []byte) {
	if len(payload) > math.MaxUint16 {
		panic(fmt.Sprintf("protocol: frame payload too large: %d", len(payload)))
	}
}

// AppendFrame 把单个帧（头部 + payload）追加到 buf，不重置已有内容。
// 这是唯一的帧编码路径：头部由 len(f.Payload) 推导而非 f.Length，
// 因此两个字段不一致的 Frame（例如刚从线上解码出来的）永远不会产生
// 损坏的记录。
func AppendFrame(buf []byte, f Frame) []byte {
	var header [FrameHeaderSize]byte
	header[0] = byte(f.Type)
	binary.BigEndian.PutUint16(header[1:3], uint16(len(f.Payload)))
	buf = append(buf, header[:]...)
	return append(buf, f.Payload...)
}

// EncodeFrames 把一组帧编码进单个新缓冲区。
func EncodeFrames(frames []Frame) []byte {
	total := 0
	for _, f := range frames {
		total += FrameHeaderSize + len(f.Payload)
	}
	buf := make([]byte, 0, total)
	for _, f := range frames {
		buf = AppendFrame(buf, f)
	}
	return buf
}
