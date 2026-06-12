package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
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
		return endpoint == "/v3/tcp"
	case ProtoUDP:
		return endpoint == "/v3/udp"
	case ProtoICMP:
		return endpoint == "/v3/icmp"
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

func ReadFrame(r io.Reader) (Frame, error) {
	var header [FrameHeaderSize]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return Frame{}, err
	}
	ftype := FrameType(header[0])
	length := binary.BigEndian.Uint16(header[1:3])

	payload := make([]byte, length)
	if length > 0 {
		if _, err := io.ReadFull(r, payload); err != nil {
			return Frame{}, err
		}
	}

	return Frame{
		Type:    ftype,
		Length:  length,
		Payload: payload,
	}, nil
}

func WriteFrame(w io.Writer, f Frame) error {
	var header [FrameHeaderSize]byte
	header[0] = byte(f.Type)
	binary.BigEndian.PutUint16(header[1:3], f.Length)
	if _, err := w.Write(header[:]); err != nil {
		return err
	}
	if f.Length > 0 {
		if _, err := w.Write(f.Payload); err != nil {
			return err
		}
	}
	return nil
}

func NewFrameDATA(data []byte) Frame {
	payload := append([]byte(nil), data...)
	return Frame{
		Type:    FrameDATA,
		Length:  uint16(len(payload)),
		Payload: payload,
	}
}

func NewFrameDATAGRAM(data []byte) Frame {
	payload := append([]byte(nil), data...)
	return Frame{
		Type:    FrameDATAGRAM,
		Length:  uint16(len(payload)),
		Payload: payload,
	}
}

func NewFrameFIN() Frame {
	return Frame{Type: FrameFIN, Length: 0}
}

func NewFrameRST() Frame {
	return Frame{Type: FrameRST, Length: 0}
}

func NewFramePADDING(length uint16) Frame {
	payload := make([]byte, length)
	return Frame{
		Type:    FramePADDING,
		Length:  length,
		Payload: payload,
	}
}

func NewFrameHANDSHAKE(h Handshake) Frame {
	payload := h.Encode()
	return Frame{
		Type:    FrameHANDSHAKE,
		Length:  uint16(len(payload)),
		Payload: payload,
	}
}

func EncodeFrames(frames []Frame) []byte {
	return EncodeFramesToBuf(frames, nil)
}

func EncodeFramesToBuf(frames []Frame, buf []byte) []byte {
	total := 0
	for _, f := range frames {
		total += f.EncodedLen()
	}
	if cap(buf) < total {
		buf = make([]byte, 0, total)
	} else {
		buf = buf[:0]
	}
	for _, f := range frames {
		var header [FrameHeaderSize]byte
		header[0] = byte(f.Type)
		binary.BigEndian.PutUint16(header[1:3], f.Length)
		buf = append(buf, header[:]...)
		buf = append(buf, f.Payload...)
	}
	return buf
}
