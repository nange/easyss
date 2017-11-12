package easypool

import (
	"net"
	"testing"
)

func TestPoolConn(t *testing.T) {
	var _ net.Conn = new(PoolConn)
}
