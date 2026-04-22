package cipherstream

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"iter"
	mr "math/rand"

	"github.com/nange/easyss/v2/util"
	"github.com/nange/easyss/v2/util/bytespool"
)

const (
	Http2HeaderLen = 9
	PaddingSize    = 64
	MaxPaddingSize = 255
	MinPaddingSize = 64
)

type FrameType uint8

const (
	FrameTypeData    FrameType = 0x0
	FrameTypeRST     FrameType = 0x3
	FrameTypePing    FrameType = 0x6
	FrameTypeUnknown FrameType = 0xff
)

func ParseFrameTypeFrom(i uint8) FrameType {
	switch FrameType(i) {
	case FrameTypeData, FrameTypePing, FrameTypeRST:
		return FrameType(i)
	default:
		return FrameTypeUnknown
	}
}

func (ft FrameType) ToUint8() uint8 {
	return uint8(ft)
}

func (ft FrameType) String() string {
	switch ft {
	case FrameTypeData:
		return "data"
	case FrameTypePing:
		return "ping"
	case FrameTypeRST:
		return "rst"
	default:
		return "unknown"
	}
}

const FlagDefault uint8 = 0
const (
	FlagTCP uint8 = 1 << iota
	FlagUDP
	FlagICMP
	FlagPad
	FlagNeedACK
	FlagFIN
	FlagACK
	FlagDNS
)

func encodeHTTP2Header(frameType FrameType, flag uint8, rawDataLen int) (header [Http2HeaderLen]byte, padSize byte) {
	dataLen := uint32(rawDataLen)
	needPad := rawDataLen <= PaddingSize
	if needPad {
		ps := util.RandomBetween(MinPaddingSize, MaxPaddingSize)
		// padding len + raw data len + padding data len
		dataLen += 1 + uint32(ps)
		padSize = byte(ps)
	}

	// set length field
	header[0] = byte(dataLen >> 16)
	header[1] = byte(dataLen >> 8)
	header[2] = byte(dataLen)
	// set frame type
	header[3] = frameType.ToUint8()
	// set default flag
	header[4] = flag
	if needPad { // data has pad field
		header[4] |= FlagPad
	}

	binary.BigEndian.PutUint32(header[5:Http2HeaderLen], uint32(mr.Int31()))

	return header, padSize
}

type Header struct {
	header [Http2HeaderLen]byte
}

// PayloadLen returns payload length in http2 header frame
func (h *Header) PayloadLen() int {
	return int(h.header[0])<<16 | int(h.header[1])<<8 | int(h.header[2])
}

// HasPad returns true if http2 header frame has pad field
func (h *Header) HasPad() bool {
	return h.header[4]&FlagPad == FlagPad
}

func (h *Header) FrameType() FrameType {
	return ParseFrameTypeFrom(h.header[3])
}

func (h *Header) IsDataFrame() bool {
	return h.FrameType() == FrameTypeData
}

func (h *Header) IsPingFrame() bool {
	return h.FrameType() == FrameTypePing
}

func (h *Header) IsRSTFINFrame() bool {
	return h.FrameType() == FrameTypeRST && h.header[4]&FlagFIN == FlagFIN
}

func (h *Header) IsRSTACKFrame() bool {
	return h.FrameType() == FrameTypeRST && h.header[4]&FlagACK == FlagACK
}

func (h *Header) IsTCPProto() bool {
	return h.header[4]&FlagTCP == FlagTCP
}

func (h *Header) IsUDPProto() bool {
	return h.header[4]&FlagUDP == FlagUDP
}

func (h *Header) IsICMPProto() bool {
	return h.header[4]&FlagICMP == FlagICMP
}

func (h *Header) IsDNSProto() bool {
	return h.IsUDPProto() && (h.header[4]&FlagDNS == FlagDNS)
}

func (h *Header) IsNeedACK() bool {
	return h.header[4]&FlagNeedACK == FlagNeedACK
}

type Payload struct {
	padSize byte
	rawData []byte
	pad     []byte
	// used for reusing bytes when padSize > 0
	padPayloadBuf []byte
}

func (p *Payload) PadSize() byte {
	return p.padSize
}

func (p *Payload) FramePayload() []byte {
	if p.padSize == 0 {
		return p.rawData
	}

	if len(p.padPayloadBuf) == 0 {
		p.padPayloadBuf = bytespool.Get(PaddingSize + MaxPaddingSize + 1)
	}
	payload := p.padPayloadBuf[:0]
	payload = append(payload, p.padSize)
	payload = append(payload, p.rawData...)
	payload = append(payload, p.pad...)

	return payload
}

func (p *Payload) RawDataPayload() []byte {
	return p.rawData
}

func (p *Payload) Pad() []byte {
	return p.pad
}

type Frame struct {
	Header
	Payload
	padBuf []byte
	cipher AEADCipher
}

func NewFrame(ft FrameType, payload []byte, flag uint8, cipher AEADCipher) *Frame {
	header, padSize := encodeHTTP2Header(ft, flag, len(payload))

	f := &Frame{
		Header: Header{header: header},
		Payload: Payload{
			padSize: padSize,
			rawData: payload,
		},
		cipher: cipher,
	}

	if padSize > 0 {
		padBuf := bytespool.Get(MaxPaddingSize)
		f.padBuf = padBuf

		pad := padBuf[:padSize]
		_, _ = rand.Read(pad)
		f.pad = pad
	}

	return f
}

func (f *Frame) EncodeWithCipher(buf []byte) ([]byte, error) {
	buf = buf[:0]
	var err error

	buf, err = f.cipher.Encrypt(buf, f.header[:])
	if err != nil {
		return nil, err
	}

	buf, err = f.cipher.Encrypt(buf, f.FramePayload())
	if err != nil {
		return nil, err
	}

	return buf, nil
}

func (f *Frame) Release() {
	if cap(f.padBuf) > 0 {
		bytespool.MustPut(f.padBuf[:cap(f.padBuf)])
		f.padBuf = nil
	}
	if cap(f.padPayloadBuf) > 0 {
		bytespool.MustPut(f.padPayloadBuf[:cap(f.padPayloadBuf)])
		f.padPayloadBuf = nil
	}
}

type FrameIter struct {
	r      io.Reader
	buf    []byte
	cipher AEADCipher
	err    error
}

func NewFrameIter(r io.Reader, cipher AEADCipher) *FrameIter {
	buf := bytespool.Get(MaxPayloadSize + cipher.NonceSize() + cipher.Overhead())

	return &FrameIter{
		r:      r,
		buf:    buf,
		cipher: cipher,
	}
}

func (fi *FrameIter) Iter() iter.Seq[*Frame] {
	return func(yield func(*Frame) bool) {
		for {
			if !yield(fi.Next()) {
				return
			}
		}
	}
}

func (fi *FrameIter) Next() *Frame {
	hBuf := fi.buf[:Http2HeaderLen+fi.cipher.NonceSize()+fi.cipher.Overhead()]
	_, err := io.ReadFull(fi.r, hBuf)
	fi.err = err
	if fi.err != nil {
		return nil
	}

	header, err := fi.cipher.Decrypt(hBuf[fi.cipher.NonceSize():][:0], hBuf)
	fi.err = err
	if fi.err != nil {
		return nil
	}

	var headerArray [Http2HeaderLen]byte
	copy(headerArray[:], header)
	fHeader := Header{header: headerArray}

	// the payload size reading from header
	size := fHeader.PayloadLen()
	if (size & MaxPayloadSize) != size {
		fi.err = ErrPayloadSize
		return nil
	}

	payloadLen := size + fi.cipher.NonceSize() + fi.cipher.Overhead()
	_, err = io.ReadFull(fi.r, fi.buf[:payloadLen])
	fi.err = err
	if err != nil {
		return nil
	}

	payloadPlain, err := fi.cipher.Decrypt(fi.buf[fi.cipher.NonceSize():][:0], fi.buf[:payloadLen])
	fi.err = err
	if fi.err != nil {
		return nil
	}

	var padSize byte
	var pad []byte
	if fHeader.HasPad() {
		padSize = payloadPlain[0]
		padStartIdx := len(payloadPlain) - int(padSize)
		if padStartIdx < 0 {
			fi.err = fmt.Errorf("pad start index is negative:%v", padStartIdx)
			return nil
		}
		pad = payloadPlain[padStartIdx:]

		ppLen := len(payloadPlain) - int(padSize) - 1
		if ppLen < 0 {
			fi.err = fmt.Errorf("payload len is negative:%v", ppLen)
			return nil
		}
		payloadPlain = payloadPlain[1 : ppLen+1]
	}

	fPayload := Payload{
		padSize: padSize,
		rawData: payloadPlain,
		pad:     pad,
	}

	return &Frame{
		Header:  fHeader,
		Payload: fPayload,
	}
}

func (fi *FrameIter) Error() error {
	return fi.err
}

func (fi *FrameIter) Release() {
	if cap(fi.buf) > 0 {
		bytespool.MustPut(fi.buf)
		fi.buf = nil
	}
}
