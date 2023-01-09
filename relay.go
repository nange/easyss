package easyss

import (
	"errors"
	"io"
	"net"
	"syscall"
	"time"

	"github.com/nange/easypool"
	"github.com/nange/easyss/cipherstream"
	"github.com/nange/easyss/util"
	log "github.com/sirupsen/logrus"
)

var connStateBytes = util.NewBytes(32)

// relay copies between cipher stream and plaintext stream.
// return the number of bytes copies
// from plaintext stream to cipher stream, from cipher stream to plaintext stream, and needClose on server conn
func (ss *Easyss) relay(cipher, plaintxt net.Conn) (n1 int64, n2 int64) {
	type res struct {
		N        int64
		Err      error
		TryReuse bool
	}

	ch1 := make(chan res, 1)
	ch2 := make(chan res, 1)

	go func() {
		n, err := io.Copy(plaintxt, cipher)
		if ce := closeWrite(plaintxt); ce != nil {
			log.Warnf("[REPAY] close write for plaintxt stream: %v", ce)
		}

		tryReuse := true
		if err != nil {
			log.Debugf("[REPAY] copy from cipher to plaintxt: %v", err)
			if !cipherstream.FINRSTStreamErr(err) {
				if err := setCipherDeadline(cipher, ss.Timeout()); err != nil {
					tryReuse = false
				} else {
					if err := readAllIgnore(cipher); !cipherstream.FINRSTStreamErr(err) {
						tryReuse = false
					}
				}
			}
		}
		ch2 <- res{N: n, Err: err, TryReuse: tryReuse}
	}()

	go func() {
		n, err := io.Copy(cipher, plaintxt)
		if err != nil {
			log.Debugf("[REPAY] copy from plaintxt to cipher: %v", err)
		}

		tryReuse := true
		if err := closeWrite(cipher); err != nil {
			tryReuse = false
			log.Warnf("[REPAY] close write for cipher stream: %v", err)
		}
		ch1 <- res{N: n, Err: err, TryReuse: tryReuse}
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
		reuse = func() bool {
			if err := setCipherDeadline(cipher, ss.Timeout()); err != nil {
				return false
			}
			if err := writeACK(cipher); err != nil {
				return false
			}
			if !readACK(cipher) {
				return false
			}
			if err := cipher.SetDeadline(time.Time{}); err != nil {
				return false
			}
			return true
		}()
	}
	if !reuse {
		markCipherStreamUnusable(cipher)
		log.Debugf("[REPAY] underlying proxy connection is unhealthy, need close it")
	} else {
		log.Infof("[REPAY] underlying proxy connection is healthy, so reuse it")
	}

	return
}

func closeWrite(conn net.Conn) error {
	if csConn, ok := conn.(*cipherstream.CipherStream); ok {
		finBuf := headerBytes.Get(util.Http2HeaderLen)
		defer headerBytes.Put(finBuf)

		fin := util.EncodeFINRstStream(finBuf)
		_, err := csConn.Write(fin)
		return err
	}

	err := conn.(*net.TCPConn).CloseWrite()
	if errorCanIgnore(err) {
		return nil
	}

	return err
}

func errorCanIgnore(err error) bool {
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
	buf := connStateBytes.Get(32)
	defer connStateBytes.Put(buf)

	var err error
	for {
		_, err = conn.Read(buf)
		if err != nil {
			break
		}
	}
	return err
}

func writeACK(conn net.Conn) error {
	ackBuf := headerBytes.Get(util.Http2HeaderLen)
	defer headerBytes.Put(ackBuf)

	ack := util.EncodeACKRstStream(ackBuf)
	_, err := conn.Write(ack)
	return err
}

func readACK(conn net.Conn) bool {
	buf := connStateBytes.Get(32)
	defer connStateBytes.Put(buf)

	var err error
	for {
		_, err = conn.Read(buf)
		if err != nil {
			break
		}
	}

	if cipherstream.ACKRSTStreamErr(err) {
		return true
	}
	return false
}

// mark the cipher stream unusable, return mark result
func markCipherStreamUnusable(cipher net.Conn) bool {
	if cs, ok := cipher.(*cipherstream.CipherStream); ok {
		if pc, ok := cs.Conn.(*easypool.PoolConn); ok {
			pc.MarkUnusable()
			return true
		}
	}
	return false
}

func setCipherDeadline(cipher net.Conn, sec time.Duration) error {
	if cs, ok := cipher.(*cipherstream.CipherStream); ok {
		return cs.Conn.SetDeadline(time.Now().Add(sec))
	}
	return nil
}
