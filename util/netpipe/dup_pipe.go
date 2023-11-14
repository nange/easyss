package netpipe

import (
	"errors"
	"net"
	"sync"
	"time"

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
	return d.Send.Close()
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
func Pipe(maxSize int) (net.Conn, net.Conn) {
	sp := &pipe{
		buf:     ringbuffer.New(maxSize),
		maxSize: maxSize,
	}
	sp.cond = *sync.NewCond(&sp.mu)

	rp := &pipe{
		buf:     ringbuffer.New(maxSize),
		maxSize: maxSize,
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
