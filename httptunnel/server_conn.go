package httptunnel

import (
	"errors"
	"net"
	"time"

	"github.com/nange/easyss/v2/httptunnel/bufpipe"
)

var _ net.Conn = (*ServerConn)(nil)

type ServerConn struct {
	reqID     string
	closeHook func(reqID string)

	local  net.Conn
	remote net.Conn
}

func NewServerConn(reqID string, closeHook func(reqID string)) *ServerConn {
	local, remote := bufpipe.ConnPipe()
	return &ServerConn{
		reqID:     reqID,
		closeHook: closeHook,
		local:     local,
		remote:    remote,
	}
}

func (c *ServerConn) ReadLocal(b []byte) (n int, err error) {
	return c.local.Read(b)
}

func (c *ServerConn) Read(b []byte) (n int, err error) {
	return c.remote.Read(b)
}

func (c *ServerConn) WriteLocal(b []byte) (n int, err error) {
	return c.local.Write(b)
}

func (c *ServerConn) Write(b []byte) (n int, err error) {
	return c.remote.Write(b)
}

func (c *ServerConn) Close() error {
	if c.closeHook != nil {
		c.closeHook(c.reqID)
	}
	c.closeHook = nil

	return errors.Join(c.local.Close(), c.remote.Close())
}

func (c *ServerConn) LocalAddr() net.Addr {
	return c.remote.LocalAddr()
}

func (c *ServerConn) RemoteAddr() net.Addr {
	return c.remote.RemoteAddr()
}

func (c *ServerConn) SetDeadline(t time.Time) error {
	return c.remote.SetDeadline(t)
}

func (c *ServerConn) SetReadDeadline(t time.Time) error {
	return c.remote.SetReadDeadline(t)
}

func (c *ServerConn) SetWriteDeadline(t time.Time) error {
	return c.remote.SetWriteDeadline(t)
}
