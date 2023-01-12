package easyss

import (
	"fmt"
	"io"
	"net"
	"strconv"

	"github.com/nange/easypool"
	"github.com/nange/easyss/cipherstream"
	"github.com/nange/easyss/util"
	"github.com/nange/easyss/util/bytespool"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/txthinking/socks5"
)

func (ss *Easyss) LocalSocks5() {
	var addr string
	if ss.BindAll() {
		addr = ":" + strconv.Itoa(ss.LocalPort())
	} else {
		addr = "127.0.0.1:" + strconv.Itoa(ss.LocalPort())
	}
	log.Infof("[SOCKS5] starting local socks5 server at %v", addr)

	server, err := socks5.NewClassicServer(addr, "127.0.0.1", "", "", 0, int(ss.Timeout()))
	if err != nil {
		log.Errorf("[SOCKS5] new socks5 server err: %+v", err)
		return
	}
	ss.SetSocksServer(server)

	if err := server.ListenAndServe(ss); err != nil {
		log.Warnf("[SOCKS5] local socks5 server:%s", err.Error())
	}
}

func (ss *Easyss) TCPHandle(s *socks5.Server, conn *net.TCPConn, r *socks5.Request) error {
	targetAddr := r.Address()
	log.Debugf("[SOCKS5] target:%v, udp:%v", targetAddr, r.Cmd == socks5.CmdUDP)

	if r.Cmd == socks5.CmdConnect {
		a, addr, port, err := socks5.ParseAddress(conn.LocalAddr().String())
		if err != nil {
			log.Errorf("[SOCKS5] socks5 ParseAddress err:%+v", err)
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
		if caddr.IP.IsLoopback() || caddr.IP.IsPrivate() || caddr.IP.IsUnspecified() {
			ch := make(chan struct{}, 2)
			portStr := strconv.FormatInt(int64(caddr.Port), 10)
			s.AssociatedUDP.Set(portStr, ch, -1)
			defer func() {
				log.Debugf("[SOCKS5] exit associate tcp connection, closing chan")
				ch <- struct{}{}
				s.AssociatedUDP.Delete(portStr)
			}()
		}

		_, _ = io.Copy(io.Discard, conn)
		log.Debugf("[SOCKS5] a tcp connection that udp %v associated closed, target addr:%v", caddr.String(), targetAddr)
		return nil
	}

	return socks5.ErrUnsupportCmd
}

func (ss *Easyss) localRelay(localConn net.Conn, addr string) (err error) {
	host, _, _ := net.SplitHostPort(addr)
	if ss.HostShouldDirect(host) {
		return ss.directRelay(localConn, addr)
	}

	log.Infof("[TCP_PROXY] target:%s", addr)
	if err := ss.validateAddr(addr); err != nil {
		log.Errorf("[TCP_PROXY] validate socks5 request:%v", err)
		return err
	}

	pool := ss.Pool()
	if pool == nil {
		return errors.New("easyss is closed")
	}

	stream, err := pool.Get()
	if err != nil {
		log.Errorf("[TCP_PROXY] get stream from pool failed:%+v", err)
		return
	}

	log.Debugf("[TCP_PROXY] after pool get, pool len: %v", pool.Len())
	defer func() {
		stream.Close()
		log.Debugf("[TCP_PROXY] after stream close, pool len: %v", pool.Len())
	}()

	if err = ss.handShakeWithRemote(stream, addr, util.ProtoTypeTCP); err != nil {
		log.Errorf("[TCP_PROXY] handshake with remote server err:%v", err)
		if pc, ok := stream.(*easypool.PoolConn); ok {
			log.Debugf("[TCP_PROXY] mark pool conn stream unusable")
			pc.MarkUnusable()
		}
		return
	}

	csStream, err := cipherstream.New(stream, ss.Password(), ss.Method(), util.ProtoTypeTCP)
	if err != nil {
		log.Errorf("[TCP_PROXY] new cipherstream err:%v, password:%v, method:%v",
			err, ss.Password(), ss.Method())
		return
	}

	n1, n2 := ss.relay(csStream, localConn)
	csStream.(*cipherstream.CipherStream).Release()

	log.Debugf("[TCP_PROXY] send %v bytes to %v, recive %v bytes", n1, addr, n2)

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

	if util.IsPrivateIP(host) {
		return fmt.Errorf("target host:%v is private ip, which is invalid", host)
	}
	if host == ss.ServerIP() && port == serverPort {
		return fmt.Errorf("target host:%v equals server host ip, which may caused infinite-loop", host)
	}

	return nil
}

func (ss *Easyss) handShakeWithRemote(stream net.Conn, addr string, protoType util.ProtoType) error {
	buf := bytespool.Get(util.Http2HeaderLen)
	defer bytespool.MustPut(buf)

	header := util.EncodeHTTP2Header(protoType, len(addr)+1, buf)
	gcm, err := cipherstream.NewAes256GCM([]byte(ss.Password()))
	if err != nil {
		return fmt.Errorf("cipherstream.NewAes256GCM err:%s", err.Error())
	}

	headerCipher, err := gcm.Encrypt(header)
	if err != nil {
		return fmt.Errorf("gcm.Encrypt err:%s", err.Error())
	}
	cipherMethod := EncodeCipherMethod(ss.Method())
	if cipherMethod == 0 {
		return fmt.Errorf("unsupported cipher method:%s", ss.Method())
	}
	payloadCipher, err := gcm.Encrypt(append([]byte(addr), cipherMethod))
	if err != nil {
		return fmt.Errorf("gcm.Encrypt err:%s", err.Error())
	}

	handshake := append(headerCipher, payloadCipher...)
	if header[4] == 0x8 { // has padding field
		padBytes := bytespool.Get(cipherstream.PaddingSize)
		defer bytespool.MustPut(padBytes)

		var padCipher []byte
		padCipher, err = gcm.Encrypt(padBytes)
		if err != nil {
			return fmt.Errorf("encrypt padding buf err:%s", err.Error())
		}
		handshake = append(handshake, padCipher...)
	}
	_, err = stream.Write(handshake)

	return err
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
