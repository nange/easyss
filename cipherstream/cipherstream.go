package cipherstream

import (
	"bytes"
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
	buf := make([]byte, bufSize)
	total := 0
	r := bytes.NewReader(b)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			ciphertxt, err := cs.Encrypt(buf[:n])
			if err != nil {
				log.Debugf("encrypt buf:%v, err:%+v", buf[:n], err)
				return 0, err
			}

			n2, err := cs.Conn.Write(ciphertxt)
			if err != nil {
				log.Debugf("conn write ciphertxt:%v, n2:%v, err:%+v", ciphertxt, n2, errors.WithStack(err))
				return 0, errors.WithStack(err)
			}

			total += n2
		}
		if err != nil {
			log.Debugf("read buf err:%+v, n:%v", errors.WithStack(err), n)
			return total, errors.WithStack(err)
		}
	}

	return total, nil
}

func (cs *CipherStream) Read(b []byte) (int, error) {
	wb := bytes.NewBuffer(b)
	buf := make([]byte, bufSize+cs.NonceSize()+cs.Overhead())
	total := 0
	for {
		n, err := cs.Conn.Read(buf)
		if n > 0 {
			plaintxt, err := cs.Decrypt(buf[:n])
			if err != nil {
				log.Debugf("decrypt buf:%v, err:%+v, n:%v", buf[:n], err, n)
				return 0, errors.WithStack(err)
			}
			n2, err := wb.Write(plaintxt)
			if err != nil {
				log.Debugf("write plaintxt:%v, err:%+v, n:%v", plaintxt, errors.WithStack(err), n2)
				return 0, errors.WithStack(err)
			}
			total += n2
		}
		if err != nil {
			log.Debugf("conn read buf, err:%+v, n:%v", errors.WithStack(err), n)
			return total, errors.WithStack(err)
		}
	}

	return total, nil
}
