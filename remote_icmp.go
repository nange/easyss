package easyss

import (
	"fmt"
	"net"
	"time"

	"github.com/nange/easyss/v2/cipherstream"
	"github.com/nange/easyss/v2/log"
	"golang.org/x/net/icmp"
)

func (es *EasyServer) remoteICMPHandle(conn net.Conn, addrStr, method string, tryReuse bool) error {
	log.Info("[REMOTE] icmp handle", "addr", addrStr)

	csStream, err := cipherstream.New(conn, es.Password(), method, cipherstream.FrameTypeData, cipherstream.FlagICMP)
	if err != nil {
		return fmt.Errorf("new cipherstream err:%v, method:%v", err, method)
	}
	cs := csStream.(*cipherstream.CipherStream)
	defer cs.Release()

	if err := csStream.SetReadDeadline(time.Now().Add(es.ICMPTimeout())); err != nil {
		return err
	}
	buf := make([]byte, 2048)
	n, err := csStream.Read(buf)
	if err != nil {
		return err
	}

	ip := net.ParseIP(addrStr)
	if ip == nil {
		return fmt.Errorf("invalid icmp target address:%s", addrStr)
	}

	pc, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return err
	}
	defer func() { _ = pc.Close() }()

	if err := pc.SetDeadline(time.Now().Add(es.Timeout())); err != nil {
		return err
	}
	if _, err := pc.WriteTo(buf[:n], &net.IPAddr{IP: ip}); err != nil {
		return err
	}

	replyBuf := make([]byte, 2048)
	n, _, err = pc.ReadFrom(replyBuf)
	if err != nil {
		return err
	}

	if _, err := csStream.Write(replyBuf[:n]); err != nil {
		return err
	}

	return nil
}
