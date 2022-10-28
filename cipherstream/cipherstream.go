package cipherstream

import (
	"bytes"
	"io"
	"net"

	"github.com/nange/easyss/util"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

const (
	// MaxPayloadSize is the maximum size of payload, set to 16KB.
	MaxPayloadSize = 1<<14 - 1

	// PaddingSize is the http2 payload padding size
	PaddingSize = 256
)

type CipherStream struct {
	net.Conn
	AEADCipher
	reader
	writer
	protoType string
}

type reader struct {
	rbuf     []byte
	leftover []byte
}

type writer struct {
	wbuf []byte
}

var rwBufBytes = util.NewBytes(MaxPayloadSize + 64)

func New(stream net.Conn, password, method, protoType string) (net.Conn, error) {
	cs := &CipherStream{Conn: stream, protoType: protoType}

	switch method {
	case "aes-256-gcm":
		var err error
		cs.AEADCipher, err = NewAes256GCM([]byte(password))
		if err != nil {
			return nil, errors.WithStack(err)
		}
	case "chacha20-poly1305":
		var err error
		cs.AEADCipher, err = NewChaCha20Poly1305([]byte(password))
		if err != nil {
			return nil, errors.WithStack(err)
		}
	default:
		return nil, errors.New("cipher method unsupported, method:" + method)
	}

	cs.reader.rbuf = rwBufBytes.Get(MaxPayloadSize + cs.NonceSize() + cs.Overhead())
	cs.writer.wbuf = rwBufBytes.Get(MaxPayloadSize + cs.NonceSize() + cs.Overhead())

	return cs, nil
}

func (cs *CipherStream) Write(b []byte) (int, error) {
	n, err := cs.ReadFrom(bytes.NewBuffer(b))
	return int(n), err
}

var dataHeaderBytes = util.NewBytes(util.Http2HeaderLen)

var paddingBytes = util.NewBytes(PaddingSize)

func (cs *CipherStream) ReadFrom(r io.Reader) (n int64, err error) {
	for {
		payloadBuf := cs.wbuf[:MaxPayloadSize]
		nr, er := r.Read(payloadBuf)

		if nr > 0 {
			n += int64(nr)

			var padding bool
			headerBuf := dataHeaderBytes.Get(util.Http2HeaderLen)
			headerBuf = util.EncodeHTTP2DataFrameHeader(cs.protoType, nr, headerBuf)
			if headerBuf[4] == 0x8 {
				padding = true
			}

			headercipher, er := cs.Encrypt(headerBuf)
			dataHeaderBytes.Put(headerBuf)
			if er != nil {
				log.Errorf("encrypt header buf err:%+v", err)
				return 0, ErrEncrypt
			}

			payloadcipher, er := cs.Encrypt(payloadBuf[:nr])
			if er != nil {
				log.Errorf("encrypt payload buf err:%+v", err)
				return 0, ErrEncrypt
			}

			dataframe := append(headercipher, payloadcipher...)
			if padding {
				padBytes := paddingBytes.Get(PaddingSize)
				padcipher, err := cs.Encrypt(padBytes)
				paddingBytes.Put(padBytes)
				if err != nil {
					log.Errorf("encrypt padding buf err:%+v", err)
					return 0, ErrEncrypt
				}

				dataframe = append(dataframe, padcipher...)
			}

			if _, ew := cs.Conn.Write(dataframe); ew != nil {
				log.Warnf("write cipher data to cipher stream failed, msg:%+v", ew)
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
				log.Debugf("read plaintext from reader failed, msg:%+v", err)
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

	payloadPlain, err := cs.read()
	if err != nil {
		return 0, err
	}

	cn := copy(b, payloadPlain)
	if cn < len(payloadPlain) {
		cs.leftover = payloadPlain[cn:]
	}

	return cn, nil
}

func (cs *CipherStream) read() ([]byte, error) {
	hBuf := cs.rbuf[:util.Http2HeaderLen+cs.NonceSize()+cs.Overhead()]
	if _, err := io.ReadFull(cs.Conn, hBuf); err != nil {
		if timeout(err) {
			return nil, ErrTimeout
		}
		if errors.Is(err, io.EOF) {
			log.Debugf("got EOF error when reading cipher stream payload len, maybe the remote-server closed the conn")
		} else {
			log.Warnf("read cipher stream payload len err:%+v", err)
		}
		return nil, ErrReadCipher
	}

	hPlain, err := cs.Decrypt(hBuf)
	if err != nil {
		log.Errorf("decrypt payload length err:%+v", err)
		return nil, ErrDecrypt
	}

	// the payload size reading from cipher stream
	size := int(hPlain[0])<<16 | int(hPlain[1])<<8 | int(hPlain[2])
	if (size & MaxPayloadSize) != size {
		log.Errorf("read from cipherstream payload size:%+v is invalid", size)
		return nil, ErrPayloadSize
	}

	payloadLen := size + cs.NonceSize() + cs.Overhead()
	if _, err := io.ReadFull(cs.Conn, cs.rbuf[:payloadLen]); err != nil {
		if timeout(err) {
			return nil, ErrTimeout
		}
		if errors.Is(err, io.EOF) {
			log.Debugf("got EOF error when reading cipher stream payload, maybe the remote-server closed the conn")
		} else {
			log.Warnf("read cipher stream payload err:%+v, lenpayload:%v", err, payloadLen)
		}
		return nil, ErrReadCipher
	}

	payloadPlain, err := cs.Decrypt(cs.rbuf[:payloadLen])
	if err != nil {
		log.Errorf("decrypt payload cipher err:%+v", err)
		return nil, ErrDecrypt
	}

	if hPlain[4] == 0x8 { // has padding field
		paddingLen := PaddingSize + cs.NonceSize() + cs.Overhead()
		if _, err := io.ReadFull(cs.Conn, cs.rbuf[:paddingLen]); err != nil {
			if timeout(err) {
				return nil, ErrTimeout
			}
			if errors.Is(err, io.EOF) {
				log.Debugf("got EOF error when reading cipher stream payload padding, maybe the remote-server closed the conn")
			} else {
				log.Warnf("read cipher stream payload padding err:%+v, lenpadding:%v", err, paddingLen)
			}
			return nil, ErrReadCipher
		}
	}

	if isRSTStream, err := rstStream(payloadPlain); isRSTStream {
		log.Debugf("receive RST_STREAM frame, we should stop reading immediately")
		return nil, err
	}

	return payloadPlain, nil
}

func (cs *CipherStream) Release() {
	rwBufBytes.Put(cs.reader.rbuf)
	rwBufBytes.Put(cs.writer.wbuf)

	cs.reader.rbuf = nil
	cs.writer.wbuf = nil
}

// rstStream check the payload is RST_STREAM
func rstStream(payload []byte) (bool, error) {
	if len(payload) != util.Http2HeaderLen {
		return false, nil
	}
	size := int(payload[0])<<16 | int(payload[1])<<8 | int(payload[2])
	if size == 4 && payload[3] == 0x7 {
		if payload[4] == 0x0 {
			log.Debugf("receive FIN_RST_STREAM frame")
			return true, ErrFINRSTStream
		}
		if payload[4] == 0x1 {
			log.Debugf("receive ACK_RST_STREAM frame")
			return true, ErrACKRSTStream
		}
	}
	return false, nil
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
