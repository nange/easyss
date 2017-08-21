package cipherstream

import (
	"io"
	"net"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

const bufSize = 512

type CipherStream struct {
	net.Conn
	AEADCipher
}

type AEADCipher interface {
	Encrypt(plaintext []byte) (ciphertext []byte, err error)
	Decrypt(ciphertext []byte) (plaintext []byte, err error)
	NonceSize() int
	Overhead() int
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

	return cs, nil
}

func (cs *CipherStream) Write(b []byte) (int, error) {
	ciphertxt, err := cs.Encrypt(b)
	if err != nil {
		log.Debugf("encrypt buf:%v, err:%+v", b, err)
		return 0, err
	}

	n, err := cs.Conn.Write(ciphertxt)
	if err != nil {
		log.Debugf("conn write ciphertxt:%v, n:%v, err:%+v", ciphertxt, n, errors.WithStack(err))
		return n, err
	}
	return n, nil
}

func (cs *CipherStream) Read(b []byte) (int, error) {
	cipherbuf := make([]byte, len(b)+cs.NonceSize()+cs.Overhead())

	total := 0
	n, err := cs.Conn.Read(cipherbuf)
	if n > 0 {
		plaintxt, err := cs.Decrypt(cipherbuf[:n])
		if err != nil {
			log.Debugf("decrypt buf:%v, err:%+v, n:%v", cipherbuf[:n], err, n)
			return 0, err
		}
		copy(b, plaintxt)
		total += len(plaintxt)
	}
	if err != nil {
		log.Debugf("conn read buf, err:%+v, n:%v", errors.WithStack(err), n)
		return total, err
	}
	return total, nil
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
