package easyss

import (
	"fmt"
	"io"
	"net"
	"strconv"

	"github.com/nange/easypool"
	"github.com/nange/easyss/cipherstream"
	"github.com/nange/easyss/util"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/txthinking/socks5"
)

var dataHeaderBytes = util.NewBytes(util.Http2HeaderLen)

func (ss *Easyss) LocalSocks5() error {
	var addr string
	if ss.BindAll() {
		addr = ":" + strconv.Itoa(ss.LocalPort())
	} else {
		addr = "127.0.0.1:" + strconv.Itoa(ss.LocalPort())
	}
	log.Infof("starting local socks5 server at %v", addr)

	server, err := socks5.NewClassicServer(addr, "127.0.0.1", "", "", 0, int(ss.Timeout()))
	if err != nil {
		log.Errorf("new socks5 server err: %+v", err)
		return err
	}
	ss.SetSocksServer(server)

	err = server.ListenAndServe(ss)
	if err != nil {
		log.Warnf("local socks5 server:%s", err.Error())
	}

	return err
}

func (ss *Easyss) TCPHandle(s *socks5.Server, conn *net.TCPConn, r *socks5.Request) error {
	targetAddr := r.Address()
	log.Infof("target addr:%v, is udp:%v", targetAddr, r.Cmd == socks5.CmdUDP)

	if r.Cmd == socks5.CmdConnect {
		a, addr, port, err := socks5.ParseAddress(conn.LocalAddr().String())
		if err != nil {
			log.Errorf("socks5 ParseAddress err:%+v", err)
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
		log.Debugf("target request is udp proto, target addr:%v, caddr:%v, conn.LocalAddr:%s, conn.RemoteAddr:%s",
			targetAddr, caddr.String(), conn.LocalAddr().String(), conn.RemoteAddr().String())
		if err != nil {
			return err
		}

		// if client udp addr isn't private ip, we do not set associated udp
		// this case may be fired by non-standard socks5 implements
		if caddr.IP.IsLoopback() || caddr.IP.IsPrivate() || caddr.IP.IsUnspecified() {
			ch := make(chan byte)
			portStr := strconv.FormatInt(int64(caddr.Port), 10)
			s.AssociatedUDP.Set(portStr, ch, -1)
			defer func() {
				log.Debugf("exit associate tcp connection, closing chan")
				close(ch)
				s.AssociatedUDP.Delete(portStr)
			}()
		}

		io.Copy(io.Discard, conn)
		log.Debugf("A tcp connection that udp %v associated closed, target addr:%v\n", caddr.String(), targetAddr)
		return nil
	}

	return socks5.ErrUnsupportCmd
}

var paddingBytes = util.NewBytes(cipherstream.PaddingSize)

func (ss *Easyss) localRelay(localConn net.Conn, addr string) (err error) {
	host, _, _ := net.SplitHostPort(addr)
	if ss.HostShouldDirect(host) {
		return ss.directRelay(localConn, addr)
	}

	if err := ss.validateAddr(addr); err != nil {
		log.Errorf("validate socks5 request:%v", err)
		return err
	}

	pool := ss.Pool()
	if pool == nil {
		return errors.New("easyss is closed")
	}

	stream, err := pool.Get()
	if err != nil {
		log.Errorf("get stream from pool failed:%+v", err)
		return
	}

	log.Debugf("after pool get: current tcp pool has %v connections", pool.Len())
	defer func() {
		stream.Close()
		log.Debugf("after stream close: current tcp pool has %v connections", pool.Len())
	}()

	if err = ss.handShakeWithRemote(stream, addr, "tcp"); err != nil {
		log.Errorf("hand-shake with remote server err:%v", err)
		if pc, ok := stream.(*easypool.PoolConn); ok {
			log.Debugf("mark pool conn stream unusable")
			pc.MarkUnusable()
		}
		return
	}

	csStream, err := cipherstream.New(stream, ss.Password(), ss.Method(), "tcp")
	if err != nil {
		log.Errorf("new cipherstream err:%+v, password:%v, method:%v",
			err, ss.Password(), ss.Method())
		return
	}

	n1, n2, needClose := ss.relay(csStream, localConn)
	csStream.(*cipherstream.CipherStream).Release()

	log.Debugf("send %v bytes to %v, and recive %v bytes", n1, addr, n2)
	if !needClose {
		log.Debugf("underlying connection is health, so reuse it")
	}

	ss.stat.BytesSend.Add(n1)
	ss.stat.BytesReceive.Add(n2)

	return
}

func (ss *Easyss) validateAddr(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid target address:%v, err:%v", addr, err)
	}

	if !util.IsIP(host) {
		if host == ss.Server() {
			return fmt.Errorf("target host equals to server host, which may caused infinite-loop")
		}
		return nil
	}

	if util.IsPrivateIP(host) {
		return fmt.Errorf("target host:%v is private ip, which is invalid", host)
	}
	if host == ss.ServerIP() {
		return fmt.Errorf("target host:%v equals server host ip, which may caused infinite-loop", host)
	}

	return nil
}

func (ss *Easyss) handShakeWithRemote(stream net.Conn, addr, protoType string) error {
	header := dataHeaderBytes.Get(util.Http2HeaderLen)
	defer dataHeaderBytes.Put(header)

	header = util.EncodeHTTP2DataFrameHeader(protoType, len(addr)+1, header)
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
		padBytes := paddingBytes.Get(cipherstream.PaddingSize)
		defer paddingBytes.Put(padBytes)

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
