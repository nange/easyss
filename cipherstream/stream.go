package cipherstream

import (
	"net"
)

type CipherStream struct {
	net.Conn
}
