package cipherstream

import (
	"bytes"
	"io"
	"net"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

// MAX_PAYLOAD_SIZE is the maximum size of payload in bytes.
const MAX_PAYLOAD_SIZE = 0x3FFF // 16*1024 - 1

type CipherStream struct {
	net.Conn
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

func New(conn net.Conn, password, method string) (net.Conn, error) {
	cs := &CipherStream{Conn: conn}

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
	cs.writer.wbuf = make([]byte, 9+cs.NonceSize()+cs.Overhead()+MAX_PAYLOAD_SIZE+cs.NonceSize()+cs.Overhead())

	return cs, nil
}

func (cs *CipherStream) Write(b []byte) (int, error) {
	n, err := cs.ReadFrom(bytes.NewBuffer(b))
	return int(n), err
}

func (cs *CipherStream) ReadFrom(r io.Reader) (int64, error) {

	return 0, nil
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
	if _, err := io.ReadFull(cs.Conn, lenbuf); err != nil {
		log.Errorf("read cipher stream payload len err:%v", err)
		return nil, err
	}

	lenplain, err := cs.Decrypt(lenbuf)
	if err != nil {
		log.Errorf("decrypt payload length err:%v", err)
		return nil, err
	}
	size := int(lenplain[0])<<16 | int(lenplain[1])<<8 | int(lenplain[2])

	if (size & MAX_PAYLOAD_SIZE) != size {
		log.Errorf("payload size:%v is invalid", size)
		return nil, errors.New("payload size is invalid")
	}

	lenpayload := size + cs.NonceSize() + cs.Overhead()
	if _, err := io.ReadFull(cs.Conn, cs.rbuf[:lenpayload]); err != nil {
		log.Errorf("read cipher stream payload err:%v", err)
		return nil, err
	}

	payloadplain, err := cs.Decrypt(cs.rbuf[:lenpayload])
	if err != nil {
		log.Errorf("decrypt payload cipher err:%+v", err)
		return nil, err
	}

	return payloadplain, nil
}

func Copy(dst net.Conn, src net.Conn) (written int64, err error) {
	buf := make([]byte, 512)
	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			nw, ew := dst.Write(buf[:nr])
			if nw > 0 {
				written += int64(nw)
			}
			if ew != nil {
				err = ew
				break
			}
		}
		if er != nil {
			if er != io.EOF {
				err = er
			}
			break
		}
	}

	return written, err
}
