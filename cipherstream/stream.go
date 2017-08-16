package cipherstream

import (
	"net"
)

type CipherStreamConn struct {
	net.Conn
}
