package http_tunnel

import (
	"net"
	"time"
)

var _ net.Conn = (*Conn)(nil)

type Conn struct {
	local  net.Conn
	remote net.Conn
}

func NewConn() *Conn {
	read, write := net.Pipe()
	return &Conn{
		local:  read,
		remote: write,
	}
}

func (c *Conn) ReadLocal(b []byte) (n int, err error) {
	return c.local.Read(b)
}

func (c *Conn) Read(b []byte) (n int, err error) {
	return c.remote.Read(b)
}

func (c *Conn) WriteLocal(b []byte) (n int, err error) {
	return c.local.Write(b)
}

func (c *Conn) Write(b []byte) (n int, err error) {
	return c.remote.Write(b)
}

func (c *Conn) Close() error {
	return c.remote.Close()
}

func (c *Conn) LocalAddr() net.Addr {
	return c.remote.LocalAddr()
}

func (c *Conn) RemoteAddr() net.Addr {
	return c.remote.RemoteAddr()
}

func (c *Conn) SetDeadline(t time.Time) error {
	return c.remote.SetDeadline(t)
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.remote.SetReadDeadline(t)
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.remote.SetWriteDeadline(t)
}
