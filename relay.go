package easyss

import (
	"io"
	"net"
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
func relay(cipher, plaintxt io.ReadWriteCloser) (n1 int64, n2 int64, needClose bool) {
	type res struct {
		N   int64
		Err error
	}
	ch1 := make(chan res, 1)
	ch2 := make(chan res, 1)

	go func() {
		n, err := io.Copy(plaintxt, cipher)
		ch2 <- res{N: n, Err: err}
	}()
	go func() {
		n, err := io.Copy(cipher, plaintxt)
		ch1 <- res{N: n, Err: err}
	}()

	var state *ConnState
	for i := 0; i < 2; i++ {
		select {
		case res1 := <-ch1:
			expireConn(cipher)
			n1 = res1.N
			err := res1.Err
			if cipherstream.EncryptErr(err) || cipherstream.WriteCipherErr(err) {
				log.Debugf("io.Copy err:%+v, maybe underline connection have been closed", err)
				markCipherStreamUnusable(cipher)
				continue
			}

			if i == 0 {
				log.Debugf("read plaintxt stream error, set start state. details:%v", err)
				buf := connStateBytes.Get(32)
				defer connStateBytes.Put(buf)
				state = NewConnState(FIN_WAIT1, buf)
			} else if err != nil {
				if !cipherstream.TimeoutErr(err) {
					log.Errorf("execpt error is net: io timeout. but get:%v", err)
				}
			}

		case res2 := <-ch2:
			expireConn(plaintxt)
			n2 = res2.N
			err := res2.Err
			if cipherstream.DecryptErr(err) || cipherstream.ReadCipherErr(err) {
				log.Debugf("io.Copy err:%+v, maybe underline connection have been closed", err)
				markCipherStreamUnusable(cipher)
				continue
			}

			if i == 0 {
				if cipherstream.FINRSTStreamErr(err) {
					log.Debugf("read cipher stream ErrFINRSTStream, set start state")
					buf := connStateBytes.Get(32)
					defer connStateBytes.Put(buf)
					state = NewConnState(CLOSE_WAIT, buf)
				} else {
					log.Errorf("execpt error is ErrFINRSTStream, but get:%v", err)
					markCipherStreamUnusable(cipher)
				}
			} else if err != nil {
				if !cipherstream.TimeoutErr(err) {
					log.Errorf("execpt error is net: io timeout. but get:%v", err)
				}
			}

		}
	}

	if cipherStreamUnusable(cipher) {
		needClose = true
		return
	}

	setCipherDeadline(cipher)
	if state == nil {
		log.Warnf("unexcepted state, some unexcepted error occor, maybe client connection is closed")
		needClose = true
		return
	}
	for stateFn := state.fn; stateFn != nil; {
		stateFn = stateFn(cipher).fn
	}
	if state.err != nil {
		log.Warnf("state err:%+v, state:%v", state.err, state.state)
		markCipherStreamUnusable(cipher)
		needClose = true
	}

	return
}

// mark the cipher stream unusable, return mark result
func markCipherStreamUnusable(cipher io.ReadWriteCloser) bool {
	if cs, ok := cipher.(*cipherstream.CipherStream); ok {
		if pc, ok := cs.ReadWriteCloser.(*easypool.PoolConn); ok {
			log.Debugf("mark cipher stream unusable")
			pc.MarkUnusable()
			return true
		}
	}
	return false
}

// return true if the cipher stream is unusable
func cipherStreamUnusable(cipher io.ReadWriteCloser) bool {
	if cs, ok := cipher.(*cipherstream.CipherStream); ok {
		if pc, ok := cs.ReadWriteCloser.(*easypool.PoolConn); ok {
			return pc.IsUnusable()
		}
	}
	return false
}

func expireConn(conn io.ReadWriteCloser) {
	if conn, ok := conn.(net.Conn); ok {
		log.Debugf("expire the plaintxt tcp connection to make the reader to be failed immediately")
		conn.SetDeadline(time.Unix(0, 0))
		return
	}

	if cs, ok := conn.(*cipherstream.CipherStream); ok {
		if conn, ok := cs.ReadWriteCloser.(net.Conn); ok {
			log.Debugf("expire the cipher tcp connection to make the reader to be failed immediately")
			conn.SetDeadline(time.Unix(0, 0))
		}
	}
}

func setCipherDeadline(cipher io.ReadWriteCloser) {
	if cs, ok := cipher.(*cipherstream.CipherStream); ok {
		if conn, ok := cs.ReadWriteCloser.(net.Conn); ok {
			log.Debugf("set cipher tcp connection deadline to 30 second later")
			conn.SetDeadline(time.Now().Add(30 * time.Second))
		}
	}
}
