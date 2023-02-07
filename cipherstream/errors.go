package cipherstream

import (
	"errors"
	"net"
)

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
