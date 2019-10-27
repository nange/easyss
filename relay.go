package easyss

import (
	"io"
	"net"
	"time"

	"github.com/nange/easypool"
	"github.com/nange/easyss/cipherstream"
	log "github.com/sirupsen/logrus"
)

// relay copies between cipherstream and plaintxtstream.
// return the number of bytes copies
// from plaintxtstream to cipherstream, from cipherstream to plaintxtstream, and needclose on server conn
func relay(cipher, plaintxt io.ReadWriteCloser) (n1 int64, n2 int64, needclose bool) {
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
RELAY:
	for i := 0; i < 2; i++ {
		select {
		case res1 := <-ch1:
			setDeadline2Now(cipher, plaintxt)
			n1 = res1.N
			err := res1.Err
			if cipherstream.EncryptErr(err) || cipherstream.WriteCipherErr(err) {
				log.Warnf("io.Copy err:%+v, maybe underline connection have been closed", err)
				markCipherStreamUnusable(cipher)
				break RELAY
			}
			if i == 0 {
				log.Infof("read plaintxt stream error, set start state. details:%v", err)
				state = NewConnState(FIN_WAIT1)
			} else if err != nil {
				if !cipherstream.TimeoutErr(err) {
					log.Errorf("execpt error is net: io timeout. but get:%v", err)
				}
			}

		case res2 := <-ch2:
			setDeadline2Now(cipher, plaintxt)
			n2 = res2.N
			err := res2.Err
			if cipherstream.DecryptErr(err) || cipherstream.ReadCipherErr(err) {
				log.Warnf("io.Copy err:%+v, maybe underline connection have been closed", err)
				markCipherStreamUnusable(cipher)
				break RELAY
			}
			if i == 0 {
				if cipherstream.FINRSTStreamErr(err) {
					log.Infof("read cipher stream ErrFINRSTStream, set start state")
					state = NewConnState(CLOSE_WAIT)
				} else {
					log.Errorf("execpt error is ErrFINRSTStream, but get:%v", err)
					markCipherStreamUnusable(cipher)
					break RELAY
				}
			}

		}
	}

	if cipherStreamUnusable(cipher) {
		needclose = true
		return
	}

	setCipherDeadline(cipher)
	if state == nil {
		log.Errorf("unexcepted state, some unexcepted error occor")
		needclose = true
		return
	}
	for statefn := state.fn; statefn != nil; {
		statefn = statefn(cipher).fn
	}
	if state.err != nil {
		log.Warnf("state err:%+v, state:%v", state.err, state.state)
		markCipherStreamUnusable(cipher)
		needclose = true
	}

	return
}

// mark the cipher stream unusable, return mark result
func markCipherStreamUnusable(cipher io.ReadWriteCloser) bool {
	if cs, ok := cipher.(*cipherstream.CipherStream); ok {
		if pc, ok := cs.ReadWriteCloser.(*easypool.PoolConn); ok {
			log.Infof("mark cipher stream unusable")
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

func setDeadline2Now(cipher, plaintxt io.ReadWriteCloser) {
	if conn, ok := plaintxt.(net.Conn); ok {
		log.Infof("set plaintxt tcp connection deadline to now")
		conn.SetDeadline(time.Now())
	}
	if cs, ok := cipher.(*cipherstream.CipherStream); ok {
		if conn, ok := cs.ReadWriteCloser.(net.Conn); ok {
			log.Infof("set cipher tcp connection deadline to now")
			conn.SetDeadline(time.Now())
		}
	}
}

func setCipherDeadline(cipher io.ReadWriteCloser) {
	if cs, ok := cipher.(*cipherstream.CipherStream); ok {
		if conn, ok := cs.ReadWriteCloser.(net.Conn); ok {
			log.Infof("set cipher tcp connection deadline to 15 second later")
			conn.SetDeadline(time.Now().Add(15 * time.Second))
		}
	}
}
