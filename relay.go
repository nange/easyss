package easyss

import (
	"errors"
	"io"
	"net"
	"syscall"
	"time"

	"github.com/nange/easypool"
	"github.com/nange/easyss/v2/cipherstream"
	"github.com/nange/easyss/v2/util"
	"github.com/nange/easyss/v2/util/bytespool"
	log "github.com/sirupsen/logrus"
)

// RelayBufferSize set to MaxCipherRelaySize
const RelayBufferSize = cipherstream.MaxCipherRelaySize
const RelayBufferSizeString = "24kb"

type closeWriter interface {
	CloseWrite() error
}

// relay copies between cipher stream and plaintext stream.
// return the number of bytes copies
// from plaintext stream to cipher stream, from cipher stream to plaintext stream, and needClose on server conn
func relay(cipher, plaintxt net.Conn, timeout time.Duration, tryReuse bool) (n1 int64, n2 int64) {
	type res struct {
		N        int64
		Err      error
		TryReuse bool
	}

	ch1 := make(chan res, 1)
	ch2 := make(chan res, 1)

	go func() {
		n, err := io.Copy(plaintxt, cipher)
		if ce := CloseWrite(plaintxt); ce != nil {
			log.Warnf("[REPAY] close write for plaintxt stream: %v", ce)
		}

		_tryReuse := tryReuse
		if _tryReuse && err != nil {
			log.Debugf("[REPAY] copy from cipher to plaintxt: %v", err)
			if !cipherstream.FINRSTStreamErr(err) {
				if err := SetCipherDeadline(cipher, time.Now().Add(timeout)); err != nil {
					_tryReuse = false
				} else {
					if err := readAllIgnore(cipher); !cipherstream.FINRSTStreamErr(err) {
						_tryReuse = false
					}
				}
			}
		}
		ch2 <- res{N: n, Err: err, TryReuse: _tryReuse}
	}()

	go func() {
		n, err := io.Copy(cipher, plaintxt)
		if err != nil {
			log.Debugf("[REPAY] copy from plaintxt to cipher: %v", err)
		}

		_tryReuse := tryReuse
		if err := CloseWrite(cipher); err != nil {
			_tryReuse = false
			log.Warnf("[REPAY] close write for cipher stream: %v", err)
		}
		ch1 <- res{N: n, Err: err, TryReuse: _tryReuse}
	}()

	var res1, res2 res
	for i := 0; i < 2; i++ {
		select {
		case res1 = <-ch1:
			n1 = res1.N
		case res2 = <-ch2:
			n2 = res2.N
		}
	}

	reuse := false
	if res1.TryReuse && res2.TryReuse {
		reuse = tryReuseFn(cipher, timeout)
	}
	if !reuse {
		MarkCipherStreamUnusable(cipher)
		if tryReuse {
			log.Warnf("[REPAY] underlying proxy connection is unhealthy, need close it")
		}
	} else {
		log.Debugf("[REPAY] underlying proxy connection is healthy, so reuse it")
	}

	return
}

func tryReuseFn(cipher net.Conn, timeout time.Duration) bool {
	if err := SetCipherDeadline(cipher, time.Now().Add(timeout)); err != nil {
		return false
	}
	if err := WriteACKToCipher(cipher); err != nil {
		return false
	}
	if !ReadACKFromCipher(cipher) {
		return false
	}
	if err := SetCipherDeadline(cipher, time.Time{}); err != nil {
		return false
	}
	return true
}

func CloseWrite(conn net.Conn) error {
	var err error
	if cw, ok := conn.(closeWriter); ok {
		if err = cw.CloseWrite(); err != nil && ErrorCanIgnore(err) {
			return nil
		}
	}
	return err
}

func ErrorCanIgnore(err error) bool {
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return true /* ignore I/O timeout */
	}
	if errors.Is(err, syscall.EPIPE) {
		return true /* ignore broken pipe */
	}
	if errors.Is(err, syscall.ECONNRESET) {
		return true /* ignore connection reset by peer */
	}
	if errors.Is(err, syscall.ENOTCONN) {
		return true /* ignore transport endpoint is not connected */
	}
	if errors.Is(err, syscall.ESHUTDOWN) {
		return true /* ignore transport endpoint shutdown */
	}

	return false
}

func readAllIgnore(conn net.Conn) error {
	buf := bytespool.Get(RelayBufferSize)
	defer bytespool.MustPut(buf)

	var err error
	for {
		_, err = conn.Read(buf)
		if err != nil {
			break
		}
	}
	return err
}

func WriteACKToCipher(conn net.Conn) error {
	if csConn, ok := conn.(*cipherstream.CipherStream); ok {
		return csConn.WriteRST(util.FlagACK)
	}
	return nil
}

func ReadACKFromCipher(conn net.Conn) bool {
	buf := bytespool.Get(RelayBufferSize)
	defer bytespool.MustPut(buf)

	var err error
	for {
		_, err = conn.Read(buf)
		if err != nil {
			break
		}
	}

	return cipherstream.ACKRSTStreamErr(err)
}

// MarkCipherStreamUnusable mark the cipher stream unusable, return true if success
func MarkCipherStreamUnusable(cipher net.Conn) bool {
	if cs, ok := cipher.(*cipherstream.CipherStream); ok {
		if pc, ok := cs.Conn.(*easypool.PoolConn); ok {
			pc.MarkUnusable()
			return true
		}
	}
	return false
}

func SetCipherDeadline(cipher net.Conn, t time.Time) error {
	if cs, ok := cipher.(*cipherstream.CipherStream); ok {
		return cs.Conn.SetDeadline(t)
	}
	return nil
}
