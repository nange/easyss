package cipherstream

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/nange/easyss/v2/util/bytespool"
	log "github.com/sirupsen/logrus"
)

const (
	// MaxPayloadSize is the maximum size of payload, set to 16KB.
	MaxPayloadSize     = 1<<14 - 1
	MaxCipherRelaySize = MaxPayloadSize + MaxPayloadSize/2
)

const (
	MethodAes256GCM        = "aes-256-gcm"
	MethodChaCha20Poly1305 = "chacha20-poly1305"
)

type CipherStream struct {
	net.Conn
	AEADCipher
	leftover  []byte
	wbuf      []byte
	frameIter *FrameIter
	frameType FrameType
	flag      uint8
}

func New(stream net.Conn, password, method string, frameType FrameType, flags ...uint8) (net.Conn, error) {
	cs := &CipherStream{Conn: stream, frameType: frameType}
	if len(flags) > 0 {
		cs.flag = flags[0]
	}

	switch method {
	case MethodAes256GCM:
		var err error
		cs.AEADCipher, err = NewAes256GCM([]byte(password))
		if err != nil {
			return cs, fmt.Errorf("new aes-256-gcm:%w", err)
		}
	case MethodChaCha20Poly1305:
		var err error
		cs.AEADCipher, err = NewChaCha20Poly1305([]byte(password))
		if err != nil {
			return cs, fmt.Errorf("new chacha20-poly1305:%w", err)
		}
	default:
		return cs, errors.New("cipher method unsupported, method:" + method)
	}

	cs.frameIter = NewFrameIter(stream, cs.AEADCipher)

	cs.wbuf = bytespool.Get(MaxPayloadSize + cs.NonceSize() + cs.Overhead())

	return cs, nil
}

func (cs *CipherStream) Write(b []byte) (int, error) {
	n, err := cs.ReadFrom(bytes.NewBuffer(b))
	return int(n), err
}

func (cs *CipherStream) WriteFrame(f *Frame) error {
	buf := bytespool.Get(MaxCipherRelaySize)
	defer bytespool.MustPut(buf)

	frameBytes, err := f.EncodeWithCipher(buf)
	if err != nil {
		log.Errorf("[CIPHERSTREAM] encode frame with cipher:%v", err)
		return err
	}

	if _, ew := cs.Conn.Write(frameBytes); ew != nil {
		log.Warnf("[CIPHERSTREAM] write cipher data to cipher stream failed, msg:%+v", ew)
		if timeout(ew) {
			return ErrTimeout
		}
		return ew
	}

	return nil
}

func (cs *CipherStream) WriteRST(flag uint8) error {
	frame := NewFrame(FrameTypeRST, nil, flag, cs.AEADCipher)
	defer frame.Release()

	return cs.WriteFrame(frame)
}

func (cs *CipherStream) WritePing(b []byte, flag uint8) error {
	frame := NewFrame(FrameTypePing, b, flag, cs.AEADCipher)
	defer frame.Release()

	return cs.WriteFrame(frame)
}

func (cs *CipherStream) ReadFrom(r io.Reader) (n int64, err error) {
	buf := bytespool.Get(MaxCipherRelaySize)
	defer bytespool.MustPut(buf)

	for {
		buf = buf[:0]
		payloadBuf := cs.wbuf[:MaxPayloadSize]

		nr, er := r.Read(payloadBuf)
		if nr > 0 {
			err = errors.Join(func() error {
				frame := NewFrame(cs.frameType, payloadBuf[:nr], cs.flag, cs.AEADCipher)
				defer frame.Release()

				frameBytes, er := frame.EncodeWithCipher(buf)
				if er != nil {
					log.Errorf("[CIPHERSTREAM] encode frame with cipher:%v", er)
					return er
				}

				if _, ew := cs.Conn.Write(frameBytes); ew != nil {
					log.Warnf("[CIPHERSTREAM] write cipher data to cipher stream failed, msg:%+v", ew)
					if timeout(ew) {
						return ErrTimeout
					}
					return ew
				}
				n += int64(nr)

				return nil
			}())
		}
		if er != nil {
			if !errors.Is(er, io.EOF) {
				log.Debugf("[CIPHERSTREAM] read plaintext from reader failed, msg:%+v", err)
				if timeout(er) {
					err = errors.Join(err, ErrTimeout)
				} else {
					err = errors.Join(err, er)
				}
			}
			break
		}
	}

	return
}

func (cs *CipherStream) Read(b []byte) (int, error) {
	if len(cs.leftover) > 0 {
		cn := copy(b, cs.leftover)
		cs.leftover = cs.leftover[cn:]
		return cn, nil
	}

	var frame *Frame
	for {
		frame = cs.frameIter.Next()
		if cs.frameIter.Error() != nil {
			if timeout(cs.frameIter.Error()) {
				return 0, errors.Join(cs.frameIter.Error(), ErrTimeout)
			}
			return 0, cs.frameIter.Error()
		}

		if frame.IsRSTFINFrame() {
			log.Debugf("[CIPHERSTREAM] receive RST_FIN frame, stop reading immediately")
			return 0, ErrFINRSTStream
		}
		if frame.IsRSTACKFrame() {
			log.Debugf("[CIPHERSTREAM] receive RST_ACK frame, stop reading immediately")
			return 0, ErrACKRSTStream
		}
		if frame.IsPingFrame() {
			log.Debugf("[CIPHERSTREAM] receive Ping frame, exec PingHook and continue to read next frame")
			continue
		}

		break
	}

	rawData := frame.RawDataPayload()
	cn := copy(b, rawData)
	if cn < len(rawData) {
		cs.leftover = rawData[cn:]
	}

	return cn, nil
}

func (cs *CipherStream) ReadFrame() (*Frame, error) {
	frame := cs.frameIter.Next()
	return frame, cs.frameIter.Error()
}

func (cs *CipherStream) Release() {
	if len(cs.wbuf) > 0 {
		bytespool.MustPut(cs.wbuf)
	}
	if cs.frameIter != nil {
		cs.frameIter.Release()
	}

	cs.Conn = nil
	cs.wbuf = nil
}

func (cs *CipherStream) Close() error {
	var err error
	if cs.Conn != nil {
		err = cs.Conn.Close()
	}
	cs.Release()
	return err
}

func (cs *CipherStream) CloseWrite() error {
	return cs.WriteRST(FlagFIN)
}

// timeout return true if err is net.Error timeout
func timeout(err error) bool {
	if err != nil {
		if er, ok := err.(net.Error); ok {
			return er.Timeout()
		}
	}
	return false
}
