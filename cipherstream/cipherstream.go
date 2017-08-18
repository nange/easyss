package cipherstream

import (
	"net"

	"github.com/pkg/errors"
)

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
		cs.Cipher = NewAes256GCM([]byte(password))
	default:
		return nil, errors.WithStack(errors.New("cipher method unsupported, method:" + method))
	}

	return cs, nil
}

func (cs *CipherStream) Write(b []byte) (int, error) {

}

func (cs *CipherStream) Read(b []byte) (int, error) {

}
