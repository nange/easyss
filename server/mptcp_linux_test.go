//go:build linux

package server

import (
	"net"
	"syscall"
	"testing"
)

// TestListenTCPDisablesMPTCP 钉住监听面不开 MPTCP：去掉 go.mod 的
// godebug multipathtcp=0 或 listenTCP 的 SetMultipathTCP(false)，
// 内核建出来的就是 IPPROTO_MPTCP socket（可被内核 TCP 漏洞利用）。
func TestListenTCPDisablesMPTCP(t *testing.T) {
	t.Parallel()

	ln, err := listenTCP("127.0.0.1:0")
	if err != nil {
		t.Fatalf("listenTCP: %v", err)
	}
	defer ln.Close() //nolint:errcheck

	tcpLn, ok := ln.(*net.TCPListener)
	if !ok {
		t.Fatalf("listener is %T, want *net.TCPListener", ln)
	}
	sc, err := tcpLn.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn: %v", err)
	}

	var sockErr error
	var proto int
	if err := sc.Control(func(fd uintptr) {
		proto, sockErr = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_PROTOCOL)
	}); err != nil {
		t.Fatalf("control: %v", err)
	}
	if sockErr != nil {
		t.Skipf("getsockopt SO_PROTOCOL: %v", sockErr)
	}
	if proto != syscall.IPPROTO_TCP {
		t.Fatalf("listener protocol = %d, want IPPROTO_TCP (%d); MPTCP 监听面没有关闭", proto, syscall.IPPROTO_TCP)
	}
}
