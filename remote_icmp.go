package easyss

import (
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/nange/easyss/v2/cipherstream"
	"github.com/nange/easyss/v2/log"
	"github.com/nange/easyss/v2/util/bytespool"
	"golang.org/x/net/icmp"
)

func (es *EasyServer) remoteICMPHandle(conn net.Conn, host, method string, tryReuse bool) error {
	log.Info("[REMOTE] icmp handle", "host", host)

	csStream, err := cipherstream.New(conn, es.Password(), method, cipherstream.FrameTypeData, cipherstream.FlagICMP)
	if err != nil {
		return fmt.Errorf("new cipherstream err:%w, method:%s", err, method)
	}

	cs := csStream.(*cipherstream.CipherStream)
	defer func() {
		_tryReuse := err == nil
		if _tryReuse && tryReuse {
			log.Info("[REMOTE_ICMP] try to reuse the connection")
			if err := tryReuseInServer(csStream, es.Timeout()); err != nil {
				log.Warn("[REMOTE_ICMP] underlying proxy connection is unhealthy, need close it", "err", err)
			} else {
				log.Info("[REMOTE_ICMP] underlying proxy connection is healthy, so reuse it")
			}
		}
		cs.Release()
	}()

	if err = csStream.SetDeadline(time.Now().Add(es.ICMPTimeout())); err != nil {
		return fmt.Errorf("set deadline err:%w", err)
	}

	frame, err := cs.ReadFrame()
	if err != nil {
		return fmt.Errorf("read frame err:%w", err)
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("invalid icmp target address:%s", host)
	}

	var pc *icmp.PacketConn
	pc, err = icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return fmt.Errorf("listen icmp packet err:%w", err)
	}
	defer func() { _ = pc.Close() }()

	if err = pc.SetDeadline(time.Now().Add(es.ICMPTimeout())); err != nil {
		return fmt.Errorf("set deadline err:%w", err)
	}
	if _, err = pc.WriteTo(frame.RawDataPayload(), &net.IPAddr{IP: ip}); err != nil {
		return fmt.Errorf("write icmp packet err:%w", err)
	}

	replyBuf := bytespool.Get(1024)
	defer bytespool.MustPut(replyBuf)

	var n int
	n, _, err = pc.ReadFrom(replyBuf)
	if err != nil {
		return fmt.Errorf("read icmp packet err:%w", err)
	}

	if _, err = csStream.Write(replyBuf[:n]); err != nil {
		return fmt.Errorf("write frame err:%w", err)
	}

	if !tryReuse {
		return nil
	}

	_ = csStream.SetDeadline(time.Now().Add(es.ICMPTimeout()))
	if _, err = csStream.Read(replyBuf); errors.Is(err, cipherstream.ErrFINRSTStream) {
		err = nil
	} else {
		return fmt.Errorf("expect finrst stream err, but got:%w", err)
	}

	return nil
}
