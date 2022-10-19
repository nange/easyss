package easyss

import (
	"io"
	"net"
	"strconv"
	"sync/atomic"

	"github.com/nange/easypool"
	"github.com/nange/easyss/cipherstream"
	"github.com/nange/easyss/util"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/txthinking/socks5"
)

var dataHeaderBytes = util.NewBytes(util.Http2HeaderLen)

func (ss *Easyss) Local() error {
	var addr string
	if ss.BindAll() {
		addr = ":" + strconv.Itoa(ss.LocalPort())
	} else {
		addr = "127.0.0.1:" + strconv.Itoa(ss.LocalPort())
	}
	log.Infof("starting local socks5 server at %v", addr)

	//socks5.Debug = true
	server, err := socks5.NewClassicServer(addr, "127.0.0.1", "", "", 0, 0)
	if err != nil {
		log.Errorf("new socks5 server err: %+v", err)
		return err
	}
	ss.socksServer = server

	if err := server.ListenAndServe(ss); err != nil {
		log.Errorf("socks5 server run err: %+v", err)
		return err
	}

	return nil
}

func (ss *Easyss) TCPHandle(s *socks5.Server, conn *net.TCPConn, r *socks5.Request) error {
	targetAddr := r.Address()
	log.Infof("target addr:%v", targetAddr)
	if targetAddr == ss.Server() {
		return errors.New("Infinite loop")
	}

	if r.Cmd == socks5.CmdConnect {
		a, addr, port, err := socks5.ParseAddress(ss.LocalAddr())
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

	return socks5.ErrUnsupportCmd
}

func (ss *Easyss) UDPHandle(s *socks5.Server, addr *net.UDPAddr, d *socks5.Datagram) error {
	return ss.handle.UDPHandle(s, addr, d)
}

var paddingBytes = util.NewBytes(cipherstream.PaddingSize)

func (ss *Easyss) localRelay(localConn net.Conn, addr string) (err error) {
	var stream io.ReadWriteCloser
	stream, err = ss.tcpPool.Get()
	if err != nil {
		log.Errorf("get stream from pool failed:%+v", err)
		return
	}

	log.Debugf("after pool get: current tcp pool has %v connections", ss.tcpPool.Len())
	defer func() {
		stream.Close()
		log.Debugf("after stream close: current tcp pool has %v connections", ss.tcpPool.Len())
	}()

	header := dataHeaderBytes.Get(util.Http2HeaderLen)
	defer dataHeaderBytes.Put(header)

	header = util.EncodeHTTP2DataFrameHeader(len(addr)+1, header)
	gcm, err := cipherstream.NewAes256GCM([]byte(ss.config.Password))
	if err != nil {
		log.Errorf("cipherstream.NewAes256GCM err:%+v", err)
		return
	}

	headerCipher, err := gcm.Encrypt(header)
	if err != nil {
		log.Errorf("gcm.Encrypt err:%+v", err)
		return
	}
	cipherMethod := EncodeCipherMethod(ss.config.Method)
	if cipherMethod == 0 {
		log.Errorf("unsupported cipher method:%+v", ss.config.Method)
		return
	}
	payloadCipher, err := gcm.Encrypt(append([]byte(addr), cipherMethod))
	if err != nil {
		log.Errorf("gcm.Encrypt err:%+v", err)
		return
	}

	handshake := append(headerCipher, payloadCipher...)
	if header[4] == 0x8 { // has padding field
		padBytes := paddingBytes.Get(cipherstream.PaddingSize)
		defer paddingBytes.Put(padBytes)

		var padcipher []byte
		padcipher, err = gcm.Encrypt(padBytes)
		if err != nil {
			log.Errorf("encrypt padding buf err:%+v", err)
			return
		}
		handshake = append(handshake, padcipher...)
	}
	_, err = stream.Write(handshake)
	if err != nil {
		log.Errorf("stream.Write err:%+v", errors.WithStack(err))
		if pc, ok := stream.(*easypool.PoolConn); ok {
			log.Debugf("mark pool conn stream unusable")
			pc.MarkUnusable()
		}
		return
	}

	csStream, err := cipherstream.New(stream, ss.config.Password, ss.config.Method)
	if err != nil {
		log.Errorf("new cipherstream err:%+v, password:%v, method:%v",
			err, ss.config.Password, ss.config.Method)
		return
	}

	n1, n2, needClose := relay(csStream, localConn)
	csStream.(*cipherstream.CipherStream).Release()

	log.Debugf("send %v bytes to %v, and recive %v bytes", n1, addr, n2)
	if !needClose {
		log.Debugf("underline connection is health, so reuse it")
	}

	atomic.AddInt64(&ss.stat.BytesSend, n1)
	atomic.AddInt64(&ss.stat.BytesRecive, n2)

	return
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
