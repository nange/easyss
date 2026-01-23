package easyss

import (
	"fmt"
	"net"
	"time"

	"github.com/nange/easyss/v2/cipherstream"
	"github.com/nange/easyss/v2/log"
	"github.com/nange/easyss/v2/util/bytespool"
	"golang.org/x/net/icmp"
)

func (es *EasyServer) remoteICMPHandle(conn net.Conn, addrStr, method string, tryReuse bool) error {
	log.Info("[REMOTE] icmp handle", "addr", addrStr)

	csStream, err := cipherstream.New(conn, es.Password(), method, cipherstream.FrameTypeData, cipherstream.FlagICMP)
	if err != nil {
		return fmt.Errorf("new cipherstream err:%v, method:%v", err, method)
	}

	cs := csStream.(*cipherstream.CipherStream)
	defer func() {
		_tryReuse := err == nil
		if _tryReuse && tryReuse {
			log.Info("[REMOTE_ICMP] try to reuse the connection")
			if err := tryReuseInServer(csStream, es.Timeout()); err != nil {
				log.Warn("[REMOTE_ICMP] underlying proxy connection is unhealthy, need close it", "err", err)
			} else {
				log.Debug("[REMOTE_ICMP] underlying proxy connection is healthy, so reuse it")
			}
		}
		cs.Release()
	}()

	if err = csStream.SetReadDeadline(time.Now().Add(es.ICMPTimeout())); err != nil {
		return fmt.Errorf("set read deadline err:%v", err)
	}

	frame, err := cs.ReadFrame()
	if err != nil {
		return fmt.Errorf("read frame err:%v", err)
	}

	ip := net.ParseIP(addrStr)
	if ip == nil {
		return fmt.Errorf("invalid icmp target address:%s", addrStr)
	}

	var pc *icmp.PacketConn
	pc, err = icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return fmt.Errorf("listen icmp packet err:%v", err)
	}
	defer func() { _ = pc.Close() }()

	if err = pc.SetDeadline(time.Now().Add(es.ICMPTimeout())); err != nil {
		return fmt.Errorf("set deadline err:%v", err)
	}
	if _, err = pc.WriteTo(frame.RawDataPayload(), &net.IPAddr{IP: ip}); err != nil {
		return fmt.Errorf("write icmp packet err:%v", err)
	}

	replyBuf := bytespool.Get(2048)
	defer bytespool.MustPut(replyBuf)

	var n int
	n, _, err = pc.ReadFrom(replyBuf)
	if err != nil {
		return fmt.Errorf("read icmp packet err:%v", err)
	}

	if _, err = csStream.Write(replyBuf[:n]); err != nil {
		return fmt.Errorf("write frame err:%v", err)
	}

	return nil
}
