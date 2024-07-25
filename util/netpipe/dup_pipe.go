package netpipe

import (
	"errors"
	"net"
	"sync"
	"time"

	"github.com/nange/easyss/v2/util/bytespool"
	"github.com/smallnest/ringbuffer"
)

type dupPipe struct {
	Send *pipe
	Recv *pipe
}

func (d dupPipe) Read(b []byte) (n int, err error) {
	return d.Recv.Read(b)
}

func (d dupPipe) Write(b []byte) (n int, err error) {
	return d.Send.Write(b)
}

func (d dupPipe) Close() error {
	return errors.Join(d.Send.Close(), d.Recv.Close())
}

func (d dupPipe) CloseWrite() error {
	return d.Send.CloseWrite()
}

func (d dupPipe) LocalAddr() net.Addr {
	return d.Send.LocalAddr()
}

func (d dupPipe) RemoteAddr() net.Addr {
	return d.Send.RemoteAddr()
}

func (d dupPipe) SetDeadline(t time.Time) error {
	err := d.Send.SetDeadline(t)
	err2 := d.Recv.SetDeadline(t)
	return errors.Join(err, err2)
}

func (d dupPipe) SetReadDeadline(t time.Time) error {
	return d.Recv.SetReadDeadline(t)
}

func (d dupPipe) SetWriteDeadline(t time.Time) error {
	return d.Send.SetWriteDeadline(t)
}

// Pipe creates an async, in-memory, full duplex network connection;
// both ends implement the Conn interface.
// Reads on one end are matched with writes on the other, copying data directly between the two;
// there is an internal buffering of size.
func Pipe(maxSize int, addrs ...net.Addr) (net.Conn, net.Conn) {
	var remoteAddr, localAddr net.Addr
	if len(addrs) == 1 {
		remoteAddr = addrs[0]
	} else if len(addrs) == 2 {
		remoteAddr = addrs[0]
		localAddr = addrs[1]
	}

	buf1 := bytespool.Get(maxSize)
	sp := &pipe{
		buf:        ringbuffer.NewBuffer(buf1),
		back:       buf1,
		rdChan:     make(chan struct{}),
		wdChan:     make(chan struct{}),
		closing:    make(chan struct{}),
		maxSize:    maxSize,
		remoteAddr: remoteAddr,
		localAddr:  localAddr,
	}
	sp.cond = *sync.NewCond(&sp.mu)

	buf2 := bytespool.Get(maxSize)
	rp := &pipe{
		buf:        ringbuffer.NewBuffer(buf2),
		back:       buf2,
		rdChan:     make(chan struct{}),
		wdChan:     make(chan struct{}),
		closing:    make(chan struct{}),
		maxSize:    maxSize,
		remoteAddr: remoteAddr,
		localAddr:  localAddr,
	}
	rp.cond = *sync.NewCond(&rp.mu)

	return &dupPipe{
			Send: sp,
			Recv: rp,
		}, &dupPipe{
			Send: rp,
			Recv: sp,
		}
}
