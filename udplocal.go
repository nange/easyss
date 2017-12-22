package main

import (
	"net"

	"github.com/nange/easyss/cipherstream"
	"github.com/nange/easyss/socks"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

var (
	ErrInvalidUDPData = errors.New("invalid udp data")
)

func (ss *Easyss) UDPLocal() {
	uc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: ss.config.LocalPort})
	if err != nil {
		log.Fatal(err)
	}
	log.Infof("starting local udp server at %v", uc.LocalAddr().String())

	for {
		data := make([]byte, 1734)
		n, ludpaddr, err := uc.ReadFromUDP(data)
		if err != nil {
			log.Errorf("local read from udp err:%v", err)
			continue
		}
		go ss.udprelay(data[:n], uc, ludpaddr)
	}
}

func (ss *Easyss) udprelay(data []byte, uc *net.UDPConn, ludpaddr *net.UDPAddr) {
	header, addr, body, err := udpDatagramDecomposition(data)
	if err != nil {
		log.Errorf("udpDatagramDecomposition err:%+v", err)
		return
	}
	log.Infof("udp target addr:%v", addr.String())

	stream, err := ss.getStream()
	if err != nil {
		log.Errorf("get stream err:%+v", err)
		return
	}
	if err := cipherstream.HandShake(stream, []byte(addr), ss.config.Method, ss.config.Password); err != nil {
		log.Errorf("cipherstream.HandShake err:%+v", err)
		return
	}

	csStream, err := cipherstream.New(stream, ss.config.Password, ss.config.Method)
	if err != nil {
		log.Errorf("new cipherstream err:%+v, password:%v, method:%v",
			err, ss.config.Password, ss.config.Method)
		return
	}
	if _, err := csStream.Write(body); err != nil {
		log.Errorf("csStream.Write err:%+v", err)
		return
	}

	datarelay := make([]byte, 1734)
	n, err := csStream.Read(datarelay)
	if err != nil {
		log.Errorf("csStream.Read err:%+v", err)
		return
	}

	udprelayData := append(header, datarelay[:n]...)
	if _, err := uc.WriteToUDP(udprelayData, ludpaddr); err != nil {
		log.Errorf("uc.WriteToUDP err:%v", err)
		return
	}
	log.Debugf("udp relay completed")
}

func udpDatagramDecomposition(data []byte) (header []byte, addr socks.Addr, body []byte, err error) {
	// data bytes: RSV(2) FRAG(1) ATYP(1) DST.ADDR(Variable)  DST.PORT(2) DATA(Variable)
	if len(data) <= (2 + 1 + 1 + net.IPv4len + 2) {
		err = ErrInvalidUDPData
		return
	}
	headerlen := 0
	atyp := data[3]
	switch atyp {
	case socks.AtypDomainName:
		// 5nd byte represents domain length
		domainlen := int(data[4])
		if len(data) <= (2 + 1 + 1 + 1 + domainlen + 2) {
			err = ErrInvalidUDPData
			return
		}
		headerlen = 2 + 1 + 1 + 1 + domainlen + 2
		addr = data[3 : 2+1+1+1+domainlen+2]

	case socks.AtypIPv4:
		headerlen = 2 + 1 + 1 + net.IPv4len + 2
		addr = data[3 : 2+1+1+net.IPv4len+2]

	case socks.AtypIPv6:
		headerlen = 2 + 1 + 1 + net.IPv6len + 2
		addr = data[3 : 2+1+1+net.IPv6len+2]
	}

	header = data[:headerlen]
	body = data[headerlen:]

	return
}
