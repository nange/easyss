package easyss

import (
	"errors"
	"io"
	"net"
	"syscall"
	"time"

	"github.com/nange/easypool"
	"github.com/nange/easyss/v2/cipherstream"
	"github.com/nange/easyss/v2/log"
	"github.com/nange/easyss/v2/util/bytespool"
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
func relay(cipher, plainTxt net.Conn, timeout time.Duration, tryReuse bool) (int64, int64, error) {
	ch1 := make(chan res, 1)
	ch2 := make(chan res, 1)
	go copyCipherToPlainTxt(plainTxt, cipher, timeout, tryReuse, ch2)
	go copyPlainTxtToCipher(cipher, plainTxt, timeout, tryReuse, ch1)

	var res1, res2 res
	var n1, n2 int64
	var err error
	for i := 0; i < 2; i++ {
		select {
		case res1 = <-ch1:
			n1 = res1.N
			err = errors.Join(err, res1.err)
		case res2 = <-ch2:
			n2 = res2.N
			err = errors.Join(err, res2.err)
		}
	}

	if res1.TryReuse && res2.TryReuse {
		reuse := tryReuseFn(cipher, timeout)
		if reuse != nil {
			MarkCipherStreamUnusable(cipher)
			log.Warn("[REPAY] underlying proxy connection is unhealthy, need close it", "reuse", reuse)
		} else {
			log.Debug("[REPAY] underlying proxy connection is healthy, so reuse it")
		}
	} else {
		MarkCipherStreamUnusable(cipher)
		if tryReuse {
			log.Warn("[REPAY] underlying proxy connection is unhealthy, need close it", "err", err)
		}
	}

	return n1, n2, err
}

type res struct {
	N        int64
	err      error
	TryReuse bool
}

func copyCipherToPlainTxt(plainTxt, cipher net.Conn, timeout time.Duration, tryReuse bool, ch chan res) {
	var err error
	n, er := io.Copy(plainTxt, cipher)
	if ce := CloseWrite(plainTxt); ce != nil {
		err = errors.Join(err, ce)
		log.Warn("[REPAY] close write for plaintxt stream", "err", ce)
	}
	if se := plainTxt.SetReadDeadline(time.Now().Add(2 * timeout)); se != nil {
		err = errors.Join(err, se)
	}

	if er != nil && !errors.Is(er, cipherstream.ErrFINRSTStream) {
		log.Debug("[REPAY] copy from cipher to plaintxt", "err", err)
		if tryReuse {
			if er = readAllIgnore(cipher, timeout); er != nil && !errors.Is(er, cipherstream.ErrFINRSTStream) {
				if !errors.Is(er, cipherstream.ErrTimeout) {
					err = errors.Join(err, er)
				}
				tryReuse = false
			}
		}
	}

	ch <- res{N: n, err: err, TryReuse: tryReuse}
}

func copyPlainTxtToCipher(cipher, plainTxt net.Conn, timeout time.Duration, tryReuse bool, ch chan res) {
	var err error
	n, er := io.Copy(cipher, plainTxt)
	if er != nil {
		log.Debug("[REPAY] copy from plaintxt to cipher", "err", err)
	}

	if er := CloseWrite(cipher); er != nil {
		tryReuse = false
		err = errors.Join(err, er)
		log.Warn("[REPAY] close write for cipher stream", "err", err)
	}
	if er := cipher.SetReadDeadline(time.Now().Add(2 * timeout)); er != nil {
		err = errors.Join(err, er)
	}

	ch <- res{N: n, err: err, TryReuse: tryReuse}
}

func tryReuseFn(cipher net.Conn, timeout time.Duration) error {
	if err := cipher.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}
	if err := WriteACKToCipher(cipher); err != nil {
		return err
	}
	if err := ReadACKFromCipher(cipher); err != nil {
		return err
	}
	if err := cipher.SetReadDeadline(time.Time{}); err != nil {
		return err
	}
	return nil
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

func readAllIgnore(conn net.Conn, timeout time.Duration) error {
	err := conn.SetReadDeadline(time.Now().Add(timeout))
	if err != nil {
		return err
	}

	buf := bytespool.Get(RelayBufferSize)
	defer bytespool.MustPut(buf)
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
		return csConn.WriteRST(cipherstream.FlagACK)
	}
	return nil
}

func ReadACKFromCipher(conn net.Conn) error {
	buf := bytespool.Get(RelayBufferSize)
	defer bytespool.MustPut(buf)

	var err error
	for {
		_, err = conn.Read(buf)
		if err != nil {
			break
		}
	}
	if errors.Is(err, cipherstream.ErrACKRSTStream) {
		return nil
	}

	return err
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
