package cipherstream

import (
	"bytes"
	"net"

	"github.com/pkg/errors"
)

const bufSize = 512

type CipherStream struct {
	net.Conn
	Cipher
}

type Cipher interface {
	Encrypt(plaintext []byte) (ciphertext []byte, err error)
	Decrypt(ciphertext []byte) (plaintext []byte, err error)
}

func New(conn net.Conn, password, method string) (net.Conn, error) {
	cs := &CipherStream{Conn: conn}

	switch method {
	case "aes-256-gcm":
		var err error
		cs.Cipher, err = NewAes256GCM([]byte(password))
		if err != nil {
			return nil, errors.WithStack(err)
		}
	default:
		return nil, errors.WithStack(errors.New("cipher method unsupported, method:" + method))
	}

	return cs, nil
}

func (cs *CipherStream) Write(b []byte) (int, error) {
	buf := make([]byte, bufSize)
	total := 0
	r := bytes.NewReader(b)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			ciphertxt, err := cs.Encrypt(buf[:n])
			if err != nil {
				return 0, errors.WithStack(err)
			}

			_, err = cs.Conn.Write(ciphertxt)
			if err != nil {
				return 0, errors.WithStack(err)
			}

			total += n
		}
		if err != nil {
			return total, errors.WithStack(err)
		}
	}

	return total, nil
}

func (cs *CipherStream) Read(b []byte) (int, error) {

	return 0, nil
}
