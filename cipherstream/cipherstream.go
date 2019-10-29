package cipherstream

import (
	"bytes"
	"io"
	"net"
	"sync"

	"github.com/nange/easyss/util"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

// MAX_PAYLOAD_SIZE is the maximum size of payload, set to 16KB.
const MAX_PAYLOAD_SIZE = 1<<14 - 1

const FRAME_HEADER_SIZE = 9

type CipherStream struct {
	io.ReadWriteCloser
	AEADCipher
	reader
	writer
}

type reader struct {
	rbuf     []byte
	leftover []byte
}

type writer struct {
	wbuf []byte
}

func New(stream io.ReadWriteCloser, password, method string) (io.ReadWriteCloser, error) {
	cs := &CipherStream{ReadWriteCloser: stream}

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

	cs.reader.rbuf = make([]byte, MAX_PAYLOAD_SIZE+cs.NonceSize()+cs.Overhead())
	cs.writer.wbuf = make([]byte, MAX_PAYLOAD_SIZE+cs.NonceSize()+cs.Overhead())

	return cs, nil
}

func (cs *CipherStream) Write(b []byte) (int, error) {
	n, err := cs.ReadFrom(bytes.NewBuffer(b))
	return int(n), err
}

var dataHeaderPool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, 9)
		return buf
	},
}

func (cs *CipherStream) ReadFrom(r io.Reader) (n int64, err error) {
	for {
		payloadBuf := cs.wbuf[:MAX_PAYLOAD_SIZE]
		nr, er := r.Read(payloadBuf)

		if nr > 0 {
			n += int64(nr)
			log.Debugf("read from normal stream, frame payload size:%v ", nr)

			headerBuf := dataHeaderPool.Get().([]byte)
			headerBuf = util.EncodeHTTP2DataFrameHeader(nr, headerBuf)
			headercipher, er := cs.Encrypt(headerBuf)
			dataHeaderPool.Put(headerBuf)
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
			if _, ew := cs.ReadWriteCloser.Write(dataframe); ew != nil {
				log.Warnf("write cipher data to cipher stream failed, msg:%+v", ew)
				if timeout(ew) {
					err = ErrTimeout
				} else {
					err = ErrWriteCipher
				}
				break
			}
			log.Debugf("write to cipher stream, frame payload size:%v", nr)
		}
		if er != nil {
			if er != io.EOF {
				log.Warnf("read plaintext from reader failed, msg:%+v", err)
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

	payloadplain, err := cs.read()
	if err != nil {
		return 0, err
	}

	cn := copy(b, payloadplain)
	if cn < len(payloadplain) {
		cs.leftover = payloadplain[cn:len(payloadplain)]
	}

	return cn, nil
}

func (cs *CipherStream) read() ([]byte, error) {
	hbuf := cs.rbuf[:FRAME_HEADER_SIZE+cs.NonceSize()+cs.Overhead()]
	if _, err := io.ReadFull(cs.ReadWriteCloser, hbuf); err != nil {
		log.Warnf("read cipher stream payload len err:%+v", err)
		if timeout(err) {
			return nil, ErrTimeout
		}
		return nil, ErrReadCipher
	}

	hplain, err := cs.Decrypt(hbuf)
	if err != nil {
		log.Errorf("decrypt payload length err:%+v", err)
		return nil, ErrDecrypt
	}

	size := int(hplain[0])<<16 | int(hplain[1])<<8 | int(hplain[2])
	log.Debugf("read from cipher stream, frame payload size:%v", size)
	if (size & MAX_PAYLOAD_SIZE) != size {
		log.Errorf("read from cipherstream payload size:%+v is invalid", size)
		return nil, ErrPayloadSize
	}

	lenpayload := size + cs.NonceSize() + cs.Overhead()
	if _, err := io.ReadFull(cs.ReadWriteCloser, cs.rbuf[:lenpayload]); err != nil {
		log.Warnf("read cipher stream payload err:%+v, lenpayload:%v", err, lenpayload)
		if timeout(err) {
			return nil, ErrTimeout
		}
		return nil, ErrReadCipher
	}

	payloadplain, err := cs.Decrypt(cs.rbuf[:lenpayload])
	if err != nil {
		log.Errorf("decrypt payload cipher err:%+v", err)
		return nil, ErrDecrypt
	}

	if isRSTStream, err := rstStream(payloadplain); isRSTStream {
		log.Infof("receive RST_STREAM frame, we should stop reading immediately")
		return nil, err
	}

	return payloadplain, nil
}

// rstStream check the payload is RST_STREAM
func rstStream(payload []byte) (bool, error) {
	if len(payload) != FRAME_HEADER_SIZE {
		return false, nil
	}
	size := int(payload[0])<<16 | int(payload[1])<<8 | int(payload[2])
	if size == 4 && payload[3] == 0x7 {
		if payload[4] == 0x0 {
			log.Infof("receive FIN_RST_STREAM frame")
			return true, ErrFINRSTStream
		}
		if payload[4] == 0x1 {
			log.Infof("receive ACK_RST_STREAM frame")
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
