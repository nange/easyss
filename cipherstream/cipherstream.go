package cipherstream

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	"github.com/nange/easypool"
	"github.com/nange/easyss/v2/log"
	"github.com/nange/easyss/v2/util"
	"github.com/nange/easyss/v2/util/bytespool"
	"github.com/nange/easyss/v2/util/netpipe"
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
		log.Error("[CIPHERSTREAM] encode frame with cipher", "err", err)
		return err
	}

	_, ew := cs.Conn.Write(frameBytes)

	if ew != nil {
		if !errors.Is(ew, netpipe.ErrPipeClosed) {
			log.Warn("[CIPHERSTREAM] write cipher data to cipher stream failed", "err", ew)
		}
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

// RandomWritePing there is a 40% chance of inserting a Ping Frame.
func (cs *CipherStream) RandomWritePing() error {
	if util.RandomBetween(0, 10) > 5 {
		return cs.WritePing([]byte(strconv.FormatInt(time.Now().UnixNano(), 10)), FlagDefault)
	}
	return nil
}

func (cs *CipherStream) ReadFrom(r io.Reader) (n int64, err error) {
	buf := bytespool.Get(MaxCipherRelaySize)
	defer bytespool.MustPut(buf)

	wbuf := bytespool.Get(MaxPayloadSize + cs.NonceSize() + cs.Overhead())
	defer bytespool.MustPut(wbuf)

	for {
		buf = buf[:0]
		payloadBuf := wbuf[:MaxPayloadSize]

		nr, er := r.Read(payloadBuf)
		if nr > 0 {
			err = errors.Join(func() error {
				frame := NewFrame(cs.frameType, payloadBuf[:nr], cs.flag, cs.AEADCipher)
				defer frame.Release()

				frameBytes, er := frame.EncodeWithCipher(buf)
				if er != nil {
					log.Error("[CIPHERSTREAM] encode frame with cipher", "err", er)
					return er
				}

				_, ew := cs.Conn.Write(frameBytes)

				if ew != nil {
					if !errors.Is(ew, netpipe.ErrPipeClosed) {
						log.Warn("[CIPHERSTREAM] write cipher data to cipher stream failed", "err", ew)
					}
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
				log.Debug("[CIPHERSTREAM] read plaintext from reader failed", "err", err)
				if timeout(er) {
					err = errors.Join(err, ErrTimeout)
				} else {
					err = errors.Join(err, er)
				}
			}
			break
		}

		if er := cs.RandomWritePing(); er != nil {
			if !errors.Is(er, netpipe.ErrPipeClosed) {
				log.Error("[CIPHERSTREAM] random write ping failed", "err", er)
			}
			err = errors.Join(err, er)
			break
		}
	}

	return
}

func (cs *CipherStream) readNextDataPayload() ([]byte, error) {
	for frame := range cs.frameIter.Iter() {
		if err := cs.frameIter.Error(); err != nil {
			if timeout(err) {
				return nil, errors.Join(err, ErrTimeout)
			}
			return nil, err
		}

		if frame.IsRSTFINFrame() {
			log.Debug("[CIPHERSTREAM] receive RST_FIN frame, stop reading immediately")
			return nil, ErrFINRSTStream
		}
		if frame.IsRSTACKFrame() {
			log.Debug("[CIPHERSTREAM] receive RST_ACK frame, stop reading immediately")
			return nil, ErrACKRSTStream
		}
		if frame.IsPingFrame() {
			log.Debug("[CIPHERSTREAM] receive Ping frame, continue to read next frame")
			continue
		}

		return frame.RawDataPayload(), nil
	}

	return nil, io.ErrUnexpectedEOF
}

func (cs *CipherStream) Read(b []byte) (int, error) {
	if len(cs.leftover) > 0 {
		cn := copy(b, cs.leftover)
		cs.leftover = cs.leftover[cn:]
		return cn, nil
	}

	rawData, err := cs.readNextDataPayload()
	if err != nil {
		return 0, err
	}

	cn := copy(b, rawData)
	if cn < len(rawData) {
		leftoverBuf := make([]byte, len(rawData)-cn)
		copy(leftoverBuf, rawData[cn:])
		cs.leftover = leftoverBuf
	}

	return cn, nil
}

func (cs *CipherStream) WriteTo(w io.Writer) (n int64, err error) {
	if len(cs.leftover) > 0 {
		cn, er := w.Write(cs.leftover)
		n += int64(cn)
		cs.leftover = cs.leftover[cn:]
		if er != nil {
			return n, er
		}
	}

	for {
		rawData, err := cs.readNextDataPayload()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return n, nil
			}
			return n, err
		}

		if len(rawData) > 0 {
			cn, er := w.Write(rawData)
			n += int64(cn)
			if er != nil {
				return n, er
			}
			if cn < len(rawData) {
				return n, io.ErrShortWrite
			}
		}
	}
}

func (cs *CipherStream) ReadFrame() (*Frame, error) {
	for frame := range cs.frameIter.Iter() {
		return frame, cs.frameIter.Error()
	}
	return nil, cs.frameIter.Error()
}

func (cs *CipherStream) Release() {
	if cs.frameIter != nil {
		cs.frameIter.Release()
	}

	cs.Conn = nil
}

func (cs *CipherStream) Close() error {
	var err error
	if cs.Conn != nil {
		err = cs.Conn.Close()
	}
	cs.Release()
	return err
}

func (cs *CipherStream) MarkConnUnusable() bool {
	if pc, ok := cs.Conn.(*easypool.PoolConn); ok {
		pc.MarkUnusable()
		return true
	}
	return false
}

func (cs *CipherStream) CloseWrite() error {
	return cs.WriteRST(FlagFIN)
}

// timeout return true if err is net.Error timeout
func timeout(err error) bool {
	if err != nil {
		var er net.Error
		if errors.As(err, &er) {
			return er.Timeout()
		}
	}
	return false
}
