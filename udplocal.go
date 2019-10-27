package easyss

import (
	"net"

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
	// TODO: add code
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
