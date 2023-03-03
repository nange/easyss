package cipherstream

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"

	"github.com/nange/easyss/v2/util"
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
	reader
	writer
	frameType util.FrameType
	flag      uint8
}

type reader struct {
	rbuf     []byte
	leftover []byte
}

type writer struct {
	wbuf []byte
}

func New(stream net.Conn, password, method string, frameType util.FrameType, flags ...uint8) (net.Conn, error) {
	cs := &CipherStream{Conn: stream, frameType: frameType}
	if len(flags) > 0 {
		cs.flag = flags[0]
	}

	switch method {
	case MethodAes256GCM:
		var err error
		cs.AEADCipher, err = NewAes256GCM([]byte(password))
		if err != nil {
			return nil, fmt.Errorf("new aes-256-gcm:%w", err)
		}
	case MethodChaCha20Poly1305:
		var err error
		cs.AEADCipher, err = NewChaCha20Poly1305([]byte(password))
		if err != nil {
			return nil, fmt.Errorf("new chacha20-poly1305:%w", err)
		}
	default:
		return nil, errors.New("cipher method unsupported, method:" + method)
	}

	cs.reader.rbuf = bytespool.Get(MaxPayloadSize + cs.NonceSize() + cs.Overhead())
	cs.writer.wbuf = bytespool.Get(MaxPayloadSize + cs.NonceSize() + cs.Overhead())

	return cs, nil
}

func (cs *CipherStream) Write(b []byte) (int, error) {
	n, err := cs.ReadFrom(bytes.NewBuffer(b))
	return int(n), err
}

func (cs *CipherStream) WriteRST(flag uint8) error {
	hc, padSize, err := cs.makeCipherHeader(util.FrameTypeRST, flag, 0)
	if err != nil {
		log.Errorf("[CIPHERSTREAM] encrypt header buf err:%+v", err)
		return ErrEncrypt
	}
	if padSize <= 0 {
		panic("invalid pad size")
	}

	pc, err := cs.makeCipherPayload(nil, padSize)
	if err != nil {
		log.Errorf("[CIPHERSTREAM] encrypt payload buf err:%+v", err)
		return ErrEncrypt
	}

	buf := bytespool.Get(MaxCipherRelaySize)
	defer bytespool.MustPut(buf)

	frame := cs.makeCipherFrame(hc, pc, buf)
	if _, ew := cs.Conn.Write(frame); ew != nil {
		log.Warnf("[CIPHERSTREAM] write cipher data to cipher stream failed, msg:%+v", ew)
		if timeout(ew) {
			return ErrTimeout
		} else {
			return ErrWriteCipher
		}
	}

	return nil
}

func (cs *CipherStream) WritePing(b []byte, flag uint8) error {
	hc, padSize, err := cs.makeCipherHeader(util.FrameTypePing, flag, len(b))
	if err != nil {
		log.Errorf("[CIPHERSTREAM] encrypt header buf err:%+v", err)
		return ErrEncrypt
	}
	if padSize <= 0 {
		panic("invalid pad size")
	}

	pc, err := cs.makeCipherPayload(b, padSize)
	if err != nil {
		log.Errorf("[CIPHERSTREAM] encrypt payload buf err:%+v", err)
		return ErrEncrypt
	}

	buf := bytespool.Get(MaxCipherRelaySize)
	defer bytespool.MustPut(buf)

	frame := cs.makeCipherFrame(hc, pc, buf)
	if _, ew := cs.Conn.Write(frame); ew != nil {
		log.Warnf("[CIPHERSTREAM] write cipher data to cipher stream failed, msg:%+v", ew)
		if timeout(ew) {
			return ErrTimeout
		} else {
			return ErrWriteCipher
		}
	}

	return nil
}

func (cs *CipherStream) ReadPing() (payload []byte, err error) {
	var header []byte
	header, payload, err = cs.read()
	if err != nil {
		return nil, err
	}
	if util.IsRSTFINFrame(header) {
		return nil, ErrFINRSTStream
	}
	if util.IsRSTACKFrame(header) {
		return nil, ErrACKRSTStream
	}
	if util.IsPingFrame(header) {
		return
	}

	return nil, errors.New("is not ping message")
}

func (cs *CipherStream) makeCipherHeader(frameType util.FrameType, flag uint8, rawDataLen int) ([]byte, byte, error) {
	headerBuf := bytespool.Get(util.Http2HeaderLen)
	defer bytespool.MustPut(headerBuf)

	hb, padSize := util.EncodeHTTP2Header(frameType, flag, rawDataLen, headerBuf)
	hc, err := cs.Encrypt(hb)
	if err != nil {
		log.Errorf("[CIPHERSTREAM] encrypt header buf err:%+v", err)
		return nil, 0, ErrEncrypt
	}

	return hc, padSize, nil
}

func (cs *CipherStream) makeCipherPayload(rawData []byte, padSize byte) ([]byte, error) {
	payload := bytespool.Get(MaxCipherRelaySize)
	defer bytespool.MustPut(payload)

	payload = payload[:0]
	if padSize > 0 {
		payload = append(payload, padSize)
	}
	if len(rawData) > 0 {
		payload = append(payload, rawData...)
	}
	if padSize > 0 {
		padBuf := bytespool.Get(util.MaxPaddingSize)
		defer bytespool.MustPut(padBuf)

		padBuf = padBuf[:padSize]
		_, _ = rand.Read(padBuf)
		payload = append(payload, padBuf...)
	}

	dc, er := cs.Encrypt(payload)
	if er != nil {
		log.Errorf("[CIPHERSTREAM] encrypt dataframe err:%+v", er)
		return nil, ErrEncrypt
	}

	return dc, nil
}

func (cs *CipherStream) makeCipherFrame(cipherHeader []byte, cipherPayload []byte, buf []byte) []byte {
	buf = buf[:0]
	buf = append(buf, cipherHeader...)
	buf = append(buf, cipherPayload...)

	return buf
}

func (cs *CipherStream) ReadFrom(r io.Reader) (n int64, err error) {
	buf := bytespool.Get(MaxCipherRelaySize)
	defer bytespool.MustPut(buf)

	for {
		buf = buf[:0]
		payloadBuf := cs.wbuf[:MaxPayloadSize]

		nr, er := r.Read(payloadBuf)
		if nr > 0 {
			n += int64(nr)

			hc, padSize, er := cs.makeCipherHeader(cs.frameType, cs.flag, nr)
			if er != nil {
				log.Errorf("[CIPHERSTREAM] encrypt header buf err:%+v", er)
				return 0, ErrEncrypt
			}

			dc, er := cs.makeCipherPayload(payloadBuf[:nr], padSize)
			if er != nil {
				log.Errorf("[CIPHERSTREAM] encrypt dataframe err:%+v", er)
				return 0, ErrEncrypt
			}

			frame := cs.makeCipherFrame(hc, dc, buf)
			if _, ew := cs.Conn.Write(frame); ew != nil {
				log.Warnf("[CIPHERSTREAM] write cipher data to cipher stream failed, msg:%+v", ew)
				if timeout(ew) {
					err = ErrTimeout
				} else {
					err = ErrWriteCipher
				}
				break
			}
		}
		if er != nil {
			if er != io.EOF {
				log.Debugf("[CIPHERSTREAM] read plaintext from reader failed, msg:%+v", err)
				if timeout(er) {
					err = ErrTimeout
				} else {
					err = ErrReadPlaintxt
				}
			}
			break
		}

	}
	return n, err
}

func (cs *CipherStream) Read(b []byte) (int, error) {
	if len(cs.leftover) > 0 {
		cn := copy(b, cs.leftover)
		cs.leftover = cs.leftover[cn:]
		return cn, nil
	}

	var header, payloadPlain []byte
	var err error
	for {
		header, payloadPlain, err = cs.read()
		if err != nil {
			return 0, err
		}
		if util.IsRSTFINFrame(header) {
			log.Debugf("[CIPHERSTREAM] receive RST_FIN frame, stop reading immediately")
			return 0, ErrFINRSTStream
		}
		if util.IsRSTACKFrame(header) {
			log.Debugf("[CIPHERSTREAM] receive RST_ACK frame, stop reading immediately")
			return 0, ErrACKRSTStream
		}
		if util.IsPingFrame(header) {
			log.Debugf("[CIPHERSTREAM] receive Ping frame, ignore it and continue to read next frame")
			continue
		}
		break
	}

	cn := copy(b, payloadPlain)
	if cn < len(payloadPlain) {
		cs.leftover = payloadPlain[cn:]
	}

	return cn, nil
}

func (cs *CipherStream) ReadHeaderAndPayload() ([]byte, []byte, error) {
	return cs.read()
}

func (cs *CipherStream) read() ([]byte, []byte, error) {
	hBuf := cs.rbuf[:util.Http2HeaderLen+cs.NonceSize()+cs.Overhead()]
	if _, err := io.ReadFull(cs.Conn, hBuf); err != nil {
		if timeout(err) {
			return nil, nil, ErrTimeout
		}
		if errors.Is(err, io.EOF) {
			log.Debugf("[CIPHERSTREAM] got EOF error when reading cipher stream payload len, maybe the remote-server closed the conn")
			return nil, nil, io.EOF
		}
		if !strings.Contains(err.Error(), "use of closed network connection") {
			log.Warnf("[CIPHERSTREAM] read cipher stream payload len err:%v", err)
		}
		return nil, nil, ErrReadCipher
	}

	header, err := cs.Decrypt(hBuf)
	if err != nil {
		log.Errorf("[CIPHERSTREAM] decrypt payload length err:%+v", err)
		return nil, nil, ErrDecrypt
	}

	// the payload size reading from header
	size := util.PayloadLen(header)
	if (size & MaxPayloadSize) != size {
		log.Errorf("[CIPHERSTREAM] read from cipherstream payload size:%+v is invalid", size)
		return nil, nil, ErrPayloadSize
	}

	payloadLen := size + cs.NonceSize() + cs.Overhead()
	if _, err := io.ReadFull(cs.Conn, cs.rbuf[:payloadLen]); err != nil {
		if timeout(err) {
			return header, nil, ErrTimeout
		}
		if errors.Is(err, io.EOF) {
			log.Debugf("[CIPHERSTREAM] got EOF error when reading cipher stream payload, maybe the remote-server closed the conn")
		} else {
			log.Warnf("[CIPHERSTREAM] read cipher stream payload err:%+v, lenpayload:%v", err, payloadLen)
		}
		return header, nil, ErrReadCipher
	}

	payloadPlain, err := cs.Decrypt(cs.rbuf[:payloadLen])
	if err != nil {
		log.Errorf("[CIPHERSTREAM] decrypt payload cipher err:%+v", err)
		return header, nil, ErrDecrypt
	}

	if util.HasPad(header) {
		padSize := int(payloadPlain[0])
		ppLen := len(payloadPlain) - padSize - 1
		if ppLen < 0 {
			log.Errorf("[CIPHERSTREAM] payload len is negative, payload len:%v, pad size:%v, payloadPlain[0]:%b, header:%b",
				len(payloadPlain), padSize, payloadPlain[0], header)
			return header, nil, errors.New("payload len is negative")
		}
		payloadPlain = payloadPlain[1 : ppLen+1]
	}

	return header, payloadPlain, nil
}

func (cs *CipherStream) Release() {
	bytespool.MustPut(cs.reader.rbuf)
	bytespool.MustPut(cs.writer.wbuf)

	cs.Conn = nil
	cs.reader.rbuf = nil
	cs.writer.wbuf = nil
}

func (cs *CipherStream) CloseWrite() error {
	return cs.WriteRST(util.FlagFIN)
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
