package easyss

import (
	"context"
	"crypto/rand"
	"net"

	"github.com/nange/easyss/v3/log"
	"github.com/quic-go/quic-go"
)

func (es *EasyServer) startQUICServer() {
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{Port: es.ServerPort()})
	if err != nil {
		log.Error("[REMOTE_QUIC] listen udp", "err", err)
		return
	}

	resetKey := quic.StatelessResetKey{}
	_, _ = rand.Read(resetKey[:])
	tr := quic.Transport{
		Conn:               udpConn,
		ConnectionIDLength: 8,
		StatelessResetKey:  &resetKey,
	}

	ln, err := tr.Listen(es.tlsConfig.Clone(), &quic.Config{
		MaxIncomingStreams: 65535,
		MaxIdleTimeout:     es.Timeout(),
	})
	if err != nil {
		log.Error("[REMOTE_QUIC] transport listen", "err", err)
		return
	}

	log.Info("[REMOTE] starting remote quic server at", "addr", es.ListenAddr())

	for {
		conn, err := ln.Accept(context.Background())
		if err != nil {
			log.Error("[REMOTE_QUIC] accept connection", "err", err)
			break
		}

		go es.handleQuicConn(conn)
	}

}

func (es *EasyServer) handleQuicConn(conn quic.Connection) {
	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			log.Error("[REMOTE_QUIC] accept stream", "err", err)
			break
		}
		go es.handleConn(&quicStream{
			Stream:     stream,
			localAddr:  conn.LocalAddr(),
			remoteAddr: conn.RemoteAddr(),
		}, true)
	}
}

type quicStream struct {
	quic.Stream
	localAddr  net.Addr
	remoteAddr net.Addr
}

// assert quicStream implements net.Conn
var _ net.Conn = (*quicStream)(nil)

func (qs *quicStream) LocalAddr() net.Addr {
	return qs.localAddr
}

func (qs *quicStream) RemoteAddr() net.Addr {
	return qs.remoteAddr
}
