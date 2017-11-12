package cipherstream

import (
	"bytes"
	"io"

	"github.com/nange/easyss/utils"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

// MAX_PAYLOAD_SIZE is the maximum size of payload, set to 16KB.
const MAX_PAYLOAD_SIZE = 1<<14 - 1

var (
	ErrEncrypt      = errors.New("encrypt data error")
	ErrDecrypt      = errors.New("decrypt data error")
	ErrWriteCipher  = errors.New("write cipher data to writer error")
	ErrReadPlaintxt = errors.New("read plaintext data from reader error")
	ErrReadCipher   = errors.New("read cipher data from reader error")
)

type CipherStream struct {
	io.ReadWriter
	AEADCipher
	reader
	writer
}

type AEADCipher interface {
	Encrypt(plaintext []byte) (ciphertext []byte, err error)
	Decrypt(ciphertext []byte) (plaintext []byte, err error)
	NonceSize() int
	Overhead() int
}

type reader struct {
	rbuf     []byte
	leftover []byte
}

type writer struct {
	wbuf []byte
}

func New(stream io.ReadWriter, password, method string) (io.ReadWriter, error) {
	cs := &CipherStream{ReadWriter: stream}

	switch method {
	case "aes-256-gcm":
		var err error
		cs.AEADCipher, err = NewAes256GCM([]byte(password))
		if err != nil {
			return nil, errors.WithStack(err)
		}
	default:
		return nil, errors.WithStack(errors.New("cipher method unsupported, method:" + method))
	}

	cs.reader.rbuf = make([]byte, MAX_PAYLOAD_SIZE+cs.NonceSize()+cs.Overhead())
	cs.writer.wbuf = make([]byte, MAX_PAYLOAD_SIZE+cs.NonceSize()+cs.Overhead())

	return cs, nil
}

func (cs *CipherStream) Write(b []byte) (int, error) {
	n, err := cs.ReadFrom(bytes.NewBuffer(b))
	return int(n), err
}

func (cs *CipherStream) ReadFrom(r io.Reader) (n int64, err error) {
	for {
		payloadBuf := cs.wbuf[:MAX_PAYLOAD_SIZE]
		nr, er := r.Read(payloadBuf)

		if nr > 0 {
			n += int64(nr)
			log.Debugf("read from normal stream, frame payload size:%v ", nr)
			headerBuf := utils.NewHTTP2DataFrameHeader(nr)
			headercipher, er := cs.Encrypt(headerBuf)
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
			if _, ew := cs.ReadWriter.Write(dataframe); ew != nil {
				log.Warnf("write cipher data to cipher stream failed, msg:%+v", errors.WithStack(ew))
				err = ErrWriteCipher
				break
			}
		}
		if er != nil {
			if er != io.EOF {
				log.Warnf("read plaintext from reader failed, msg:%+v", errors.WithStack(er))
				err = ErrReadPlaintxt
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
	lenbuf := cs.rbuf[:9+cs.NonceSize()+cs.Overhead()]
	if _, err := io.ReadFull(cs.ReadWriter, lenbuf); err != nil {
		log.Warnf("read cipher stream payload len err:%+v", errors.WithStack(err))
		return nil, ErrReadCipher
	}

	lenplain, err := cs.Decrypt(lenbuf)
	if err != nil {
		log.Errorf("decrypt payload length err:%+v", err)
		return nil, ErrDecrypt
	}

	size := int(lenplain[0])<<16 | int(lenplain[1])<<8 | int(lenplain[2])
	log.Debugf("read from cipher stream, frame payload size:%v", size)
	if (size & MAX_PAYLOAD_SIZE) != size {
		log.Errorf("read from cipherstream payload size:%+v is invalid", size)
		return nil, errors.New("payload size is invalid")
	}

	lenpayload := size + cs.NonceSize() + cs.Overhead()
	if _, err := io.ReadFull(cs.ReadWriter, cs.rbuf[:lenpayload]); err != nil {
		log.Warnf("read cipher stream payload err:%+v, lenpayload:%v", errors.WithStack(err), lenpayload)
		return nil, ErrReadCipher
	}

	payloadplain, err := cs.Decrypt(cs.rbuf[:lenpayload])
	if err != nil {
		log.Errorf("decrypt payload cipher err:%+v", err)
		return nil, ErrDecrypt
	}

	return payloadplain, nil
}
