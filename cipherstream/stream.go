package cipherstream

import (
	"crypto/cipher"
	"net"

	"github.com/pkg/errors"
)

type CipherStream struct {
	net.Conn
	cipher.AEAD
}

func New(conn net.Conn, password, method string) (net.Conn, error) {
	cs := CipherStream{Conn: conn}

	switch method {
	case "aes-256-gcm":
		cs.AEAD = NewGCM(password)
	default:
		return nil, errors.WithStack(errors.New("cipher method unsupported, method:" + method))
	}

	return cs, nil
}
