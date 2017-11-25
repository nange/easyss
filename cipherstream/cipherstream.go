package cipherstream

import (
	"bytes"
	"io"
	"net"

	"github.com/nange/easyss/utils"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

// MAX_PAYLOAD_SIZE is the maximum size of payload, set to 16KB.
const MAX_PAYLOAD_SIZE = 1<<14 - 1

const FRAME_HEADER_SIZE = 9

var (
	ErrEncrypt      = errors.New("encrypt data error")
	ErrDecrypt      = errors.New("decrypt data error")
	ErrWriteCipher  = errors.New("write cipher data to writer error")
	ErrReadPlaintxt = errors.New("read plaintext data from reader error")
	ErrReadCipher   = errors.New("read cipher data from reader error")
	ErrFINRSTStream = errors.New("receive FIN_RST_STREAM frame")
	ErrACKRSTStream = errors.New("receive ACK_RST_STREAM frame")
	ErrTimeout      = errors.New("net: io timeout error")
	ErrPayloadSize  = errors.New("payload size is invalid")
)

type CipherStream struct {
	io.ReadWriteCloser
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

func New(stream io.ReadWriteCloser, password, method string) (io.ReadWriteCloser, error) {
	cs := &CipherStream{ReadWriteCloser: stream}

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
			if _, ew := cs.ReadWriteCloser.Write(dataframe); ew != nil {
				log.Warnf("write cipher data to cipher stream failed, msg:%+v", errors.WithStack(ew))
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
	hbuf := cs.rbuf[:FRAME_HEADER_SIZE+cs.NonceSize()+cs.Overhead()]
	if _, err := io.ReadFull(cs.ReadWriteCloser, hbuf); err != nil {
		log.Warnf("read cipher stream payload len err:%+v", errors.WithStack(err))
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
		log.Warnf("read cipher stream payload err:%+v, lenpayload:%v", errors.WithStack(err), lenpayload)
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

// EncryptErr return true if err is ErrEncrypt
func EncryptErr(err error) bool {
	if err == nil {
		return false
	}
	if err == ErrEncrypt {
		return true
	}

	if er, ok := err.(*net.OpError); ok {
		if er.Err == ErrEncrypt {
			return true
		}
	}
	return false
}

// DecryptErr return true if err is ErrDecrypt
func DecryptErr(err error) bool {
	if err == nil {
		return false
	}
	if err == ErrDecrypt {
		return true
	}

	if er, ok := err.(*net.OpError); ok {
		if er.Err == ErrDecrypt {
			return true
		}
	}
	return false
}

// WriteCipherErr return true if err is ErrWriteCipher
func WriteCipherErr(err error) bool {
	if err == nil {
		return false
	}
	if err == ErrWriteCipher {
		return true
	}

	if er, ok := err.(*net.OpError); ok {
		if er.Err == ErrWriteCipher {
			return true
		}
	}
	return false
}

// ReadPlaintxtErr return true if err is ErrReadPlaintxt
func ReadPlaintxtErr(err error) bool {
	if err == nil {
		return false
	}
	if err == ErrReadPlaintxt {
		return true
	}

	if er, ok := err.(*net.OpError); ok {
		if er.Err == ErrReadPlaintxt {
			return true
		}
	}
	return false
}

// ReadCipherErr return true if err is ErrReadCipher
func ReadCipherErr(err error) bool {
	if err == nil {
		return false
	}
	if err == ErrReadCipher {
		return true
	}

	if er, ok := err.(*net.OpError); ok {
		if er.Err == ErrReadCipher {
			return true
		}
	}
	return false
}

// FINRSTStreamErr return true if err is ErrFINRSTStream
func FINRSTStreamErr(err error) bool {
	if err == nil {
		return false
	}
	if err == ErrFINRSTStream {
		return true
	}

	if er, ok := err.(*net.OpError); ok {
		if er.Err == ErrFINRSTStream {
			return true
		}
	}
	return false
}

// ACKRSTStreamErr return true if err is ErrACKRSTStream
func ACKRSTStreamErr(err error) bool {
	if err == nil {
		return false
	}
	if err == ErrACKRSTStream {
		return true
	}

	if er, ok := err.(*net.OpError); ok {
		if er.Err == ErrACKRSTStream {
			return true
		}
	}
	return false
}

// TimeoutErr return true if err is ErrTimeout
func TimeoutErr(err error) bool {
	if err == nil {
		return false
	}
	if err == ErrTimeout {
		return true
	}

	if er, ok := err.(*net.OpError); ok {
		if er.Err == ErrTimeout {
			return true
		}
	}
	return false
}

// PayloadSizeErr return true if err is ErrPayloadSize
func PayloadSizeErr(err error) bool {
	if err == nil {
		return false
	}
	if err == ErrPayloadSize {
		return true
	}

	if er, ok := err.(*net.OpError); ok {
		if er.Err == ErrPayloadSize {
			return true
		}
	}
	return false
}
