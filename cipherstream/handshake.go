package cipherstream

import (
	"io"

	"github.com/nange/easypool"
	"github.com/nange/easyss/util"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

func HandShake(stream io.ReadWriteCloser, addr []byte, method, password string) error {
	header := util.NewHTTP2DataFrameHeader(len(addr) + 1)
	gcm, err := NewAes256GCM([]byte(password))
	if err != nil {
		log.Errorf("cipherstream.NewAes256GCM err:%+v", err)
		return err
	}

	headercipher, err := gcm.Encrypt(header)
	if err != nil {
		log.Errorf("gcm.Encrypt err:%+v", err)
		return err
	}
	ciphermethod := EncodeCipherMethod(method)
	if ciphermethod == 0 {
		log.Errorf("unsupported cipher method:%+v", method)
		return errors.New("unsupported cipher method " + method)
	}
	payloadcipher, err := gcm.Encrypt(append([]byte(addr), ciphermethod))
	if err != nil {
		log.Errorf("gcm.Encrypt err:%+v", err)
		return err
	}

	handshake := append(headercipher, payloadcipher...)
	_, err = stream.Write(handshake)
	if err != nil {
		log.Errorf("stream.Write err:%+v", errors.WithStack(err))
		if pc, ok := stream.(*easypool.PoolConn); ok {
			log.Infof("mark pool conn stream unusable")
			pc.MarkUnusable()
		}
		return err
	}

	return nil
}

func EncodeCipherMethod(m string) byte {
	methodMap := map[string]byte{
		"aes-256-gcm":       1,
		"chacha20-poly1305": 2,
	}
	if b, ok := methodMap[m]; ok {
		return b
	}
	return 0
}
