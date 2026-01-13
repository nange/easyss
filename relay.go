package easyss

import (
	"context"
	"errors"
	"io"
	"net"
	"syscall"
	"time"

	"github.com/nange/easyss/v2/cipherstream"
	"github.com/nange/easyss/v2/log"
	"github.com/nange/easyss/v2/util/bytespool"
	"github.com/nange/easyss/v2/util/netpipe"
	"github.com/negrel/conc"
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
	jobs := []conc.Job[res]{
		func(_ context.Context) (res, error) {
			return copyPlainTxtToCipher(cipher, plainTxt, timeout, tryReuse), nil
		},
		func(_ context.Context) (res, error) {
			return copyCipherToPlainTxt(plainTxt, cipher, timeout, tryReuse), nil
		},
	}

	results, _ := conc.All(jobs)
	res1, res2 := results[0], results[1]

	n1, n2 := res1.N, res2.N
	err := errors.Join(res1.err, res2.err)

	if res1.TryReuse && res2.TryReuse {
		reuse := tryReuseFn(cipher, timeout)
		if reuse != nil {
			if cs, ok := cipher.(*cipherstream.CipherStream); ok {
				cs.MarkConnUnusable()
			}
			log.Warn("[REPAY] underlying proxy connection is unhealthy, need close it", "reuse", reuse)
		} else {
			log.Debug("[REPAY] underlying proxy connection is healthy, so reuse it")
		}
	} else {
		if cs, ok := cipher.(*cipherstream.CipherStream); ok {
			cs.MarkConnUnusable()
		}
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

func copyCipherToPlainTxt(plainTxt, cipher net.Conn, timeout time.Duration, tryReuse bool) res {
	var err error
	n, er := io.Copy(plainTxt, cipher)
	if ce := CloseWrite(plainTxt); ce != nil {
		err = errors.Join(err, ce)
		log.Warn("[REPAY] close write for plaintxt stream", "err", ce)
	}
	if se := plainTxt.SetReadDeadline(time.Now().Add(3 * timeout)); se != nil {
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

	return res{N: n, err: err, TryReuse: tryReuse}
}

func copyPlainTxtToCipher(cipher, plainTxt net.Conn, timeout time.Duration, tryReuse bool) res {
	var err error
	n, er := io.Copy(cipher, plainTxt)
	if er != nil {
		log.Debug("[REPAY] copy from plaintxt to cipher", "err", err)
	}

	if er := CloseWrite(cipher); er != nil {
		tryReuse = false
		err = errors.Join(err, er)
		if !errors.Is(er, netpipe.ErrPipeClosed) {
			log.Warn("[REPAY] close write for cipher stream", "err", err)
		}
	}
	if er := cipher.SetReadDeadline(time.Now().Add(3 * timeout)); er != nil {
		err = errors.Join(err, er)
	}

	return res{N: n, err: err, TryReuse: tryReuse}
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
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
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
