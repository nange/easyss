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
func (ss *Easyss) relay(cipher, plaintxt net.Conn) (n1 int64, n2 int64, needClose bool) {
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
				log.Debugf("io.Copy err:%+v, maybe underlying connection has been closed", err)
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
				log.Debugf("io.Copy err:%+v, maybe underlying connection has been closed", err)
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

	setCipherDeadline(cipher, ss.Timeout())
	if state == nil {
		log.Infof("unexcepted state, some unexcepted error occor, maybe client connection is closed")
		needClose = true
		return
	}
	for stateFn := state.fn; stateFn != nil; {
		stateFn = stateFn(cipher).fn
	}
	if state.err != nil {
		log.Infof("state err:%v, state:%v", state.err, state.state)
		markCipherStreamUnusable(cipher)
		needClose = true
	}

	return
}

// mark the cipher stream unusable, return mark result
func markCipherStreamUnusable(cipher net.Conn) bool {
	if cs, ok := cipher.(*cipherstream.CipherStream); ok {
		if pc, ok := cs.Conn.(*easypool.PoolConn); ok {
			log.Debugf("mark cipher stream unusable")
			pc.MarkUnusable()
			return true
		}
	}
	return false
}

// return true if the cipher stream is unusable
func cipherStreamUnusable(cipher net.Conn) bool {
	if cs, ok := cipher.(*cipherstream.CipherStream); ok {
		if pc, ok := cs.Conn.(*easypool.PoolConn); ok {
			return pc.IsUnusable()
		}
	}
	return false
}

func expireConn(conn net.Conn) {
	log.Debugf("expire the connection to make the reader to be failed immediately")
	conn.SetDeadline(time.Unix(0, 0))
}

func setCipherDeadline(cipher net.Conn, sec time.Duration) {
	if cs, ok := cipher.(*cipherstream.CipherStream); ok {
		log.Debugf("set cipher tcp connection deadline to 30 second later")
		cs.Conn.SetDeadline(time.Now().Add(sec))
	}
}
