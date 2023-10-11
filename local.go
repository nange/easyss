package easyss

import (
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	"github.com/nange/easyss/v2/cipherstream"
	"github.com/nange/easyss/v2/log"
	"github.com/nange/easyss/v2/util"
	"github.com/txthinking/socks5"
)

func (ss *Easyss) LocalSocks5() {
	var addr string
	if ss.BindAll() {
		addr = ":" + strconv.Itoa(ss.LocalPort())
	} else {
		addr = "127.0.0.1:" + strconv.Itoa(ss.LocalPort())
	}
	log.Info("[SOCKS5] starting local socks5 server at", "addr", addr)

	server, err := socks5.NewClassicServer(addr, "127.0.0.1", ss.AuthUsername(), ss.AuthPassword(), 0, 0)
	if err != nil {
		log.Error("[SOCKS5] new socks5 server", "err", err)
		return
	}
	ss.SetSocksServer(server)

	if err := server.ListenAndServe(ss); err != nil {
		log.Warn("[SOCKS5] local socks5 server", "err", err)
	}
}

func (ss *Easyss) TCPHandle(s *socks5.Server, conn *net.TCPConn, r *socks5.Request) error {
	targetAddr := r.Address()
	log.Debug("[SOCKS5]", "target", targetAddr, "is_udp", r.Cmd == socks5.CmdUDP)

	if r.Cmd == socks5.CmdConnect {
		a, addr, port, err := socks5.ParseAddress(conn.LocalAddr().String())
		if err != nil {
			log.Error("[SOCKS5] socks5 ParseAddress", "err", err)
			return err
		}
		p := socks5.NewReply(socks5.RepSuccess, a, addr, port)
		if _, err := p.WriteTo(conn); err != nil {
			return err
		}

		return ss.localRelay(conn, targetAddr)
	}

	if r.Cmd == socks5.CmdUDP {
		uaddr, _ := net.ResolveUDPAddr("udp", conn.LocalAddr().String())
		caddr, err := r.UDP(conn, uaddr)
		if err != nil {
			return err
		}

		// if client udp addr isn't private ip, we do not set associated udp
		// this case may be fired by non-standard socks5 implements
		if caddr.(*net.UDPAddr).IP.IsLoopback() || caddr.(*net.UDPAddr).IP.IsPrivate() ||
			caddr.(*net.UDPAddr).IP.IsUnspecified() {
			ch := make(chan struct{}, 2)
			portStr := strconv.FormatInt(int64(caddr.(*net.UDPAddr).Port), 10)
			s.AssociatedUDP.Set(portStr, ch, -1)
			defer func() {
				log.Debug("[SOCKS5] exit associate tcp connection, closing chan")
				ch <- struct{}{}
				s.AssociatedUDP.Delete(portStr)
			}()
		}

		_, _ = io.Copy(io.Discard, conn)
		log.Debug("[SOCKS5] a tcp connection that udp associated closed",
			"udp_addr", caddr.String(), "target_addr", targetAddr)
		return nil
	}

	return socks5.ErrUnsupportCmd
}

func (ss *Easyss) localRelay(localConn net.Conn, addr string) (err error) {
	host, _, _ := net.SplitHostPort(addr)
	if ss.HostShouldDirect(host) {
		return ss.directRelay(localConn, addr)
	}

	log.Info("[TCP_PROXY]", "target", addr)
	if !ss.disableValidateAddr {
		if err := ss.validateAddr(addr); err != nil {
			log.Error("[TCP_PROXY] validate socks5 request", "err", err)
			return err
		}
	}

	csStream, err := ss.handShakeWithRemote(addr, cipherstream.FlagTCP)
	if err != nil {
		log.Warn("[TCP_PROXY] handshake with remote server", "err", err)
		if csStream != nil {
			MarkCipherStreamUnusable(csStream)
			csStream.Close()
		}
		return
	}
	defer csStream.Close()

	tryReuse := true
	if !ss.IsNativeOutboundProto() {
		tryReuse = false
	}
	n1, n2, err := relay(csStream, localConn, ss.Timeout(), tryReuse)

	log.Debug("[TCP_PROXY] send bytes to, receive bytes", "send", n1, "to", addr, "receive", n2, "err", err)

	ss.stat.BytesSend.Add(n1)
	ss.stat.BytesReceive.Add(n2)

	return
}

func (ss *Easyss) validateAddr(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid target address:%v, err:%v", addr, err)
	}

	serverPort := strconv.FormatInt(int64(ss.ServerPort()), 10)
	if !util.IsIP(host) {
		if host == ss.Server() && port == serverPort {
			return fmt.Errorf("target host,port equals to server host,port, which may caused infinite-loop")
		}
		return nil
	}

	if util.IsLANIP(host) {
		return fmt.Errorf("target host:%v is LAN ip, which is invalid", host)
	}
	if ss.DisableIPV6() && util.IsIPV6(host) {
		return fmt.Errorf("target %s is ipv6, but ipv6 network is disabled", host)
	}
	if host == ss.ServerIP() && port == serverPort {
		return fmt.Errorf("target host:%v equals server host ip, which may caused infinite-loop", host)
	}

	return nil
}

func (ss *Easyss) handShakeWithRemote(addr string, flag uint8) (net.Conn, error) {
	stream, err := ss.AvailableConn()
	if err != nil {
		log.Error("[TCP_PROXY] get stream from pool failed", "err", err)
		return nil, err
	}

	csStream, err := func() (*cipherstream.CipherStream, error) {
		cs, err := cipherstream.New(stream, ss.Password(), cipherstream.MethodAes256GCM, cipherstream.FrameTypeData, flag)
		csStream := cs.(*cipherstream.CipherStream)
		if err != nil {
			log.Error("[TCP_PROXY] new cipherstream", "err", err)
			return csStream, err
		}

		cipherMethod := EncodeCipherMethod(ss.Method())
		frame := cipherstream.NewFrame(cipherstream.FrameTypeData, append([]byte(addr), cipherMethod), flag, csStream.AEADCipher)
		if err := csStream.WriteFrame(frame); err != nil {
			return csStream, err
		}

		if err := csStream.SetReadDeadline(time.Now().Add(ss.PingTimeout())); err != nil {
			return csStream, err
		}
		frame, err = csStream.ReadFrame()
		if err != nil {
			return csStream, err
		}
		if !frame.IsPingFrame() {
			return csStream, fmt.Errorf("except got ping frame, but got %v", frame.FrameType())
		}
		if err := ss.PingHook(frame.RawDataPayload()); err != nil {
			return csStream, err
		}

		return csStream, csStream.SetReadDeadline(time.Time{})
	}()
	if err != nil {
		return csStream, err
	}
	csStream.Release()

	return cipherstream.New(stream, ss.Password(), ss.Method(), cipherstream.FrameTypeData, flag)
}

func EncodeCipherMethod(m string) byte {
	switch m {
	case "aes-256-gcm":
		return 1
	case "chacha20-poly1305":
		return 2
	default:
		return 0
	}
}
