package socks

import (
	"io"
	"net"
	"strconv"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

// SOCKS request commands as defined in RFC 1928 section 4
const (
	CmdConnect      = 1
	CmdBind         = 2
	CmdUDPAssociate = 3
)

// SOCKS address types as defined in RFC 1928 section 5.
const (
	AtypIPv4       = 1
	AtypDomainName = 3
	AtypIPv6       = 4
)

type SocksError int

var errMap = map[SocksError]string{
	ErrGeneralFailure:       "general SOCKS server failure(01)",
	ErrConnectionNotAllowed: "connection not allowed by ruleset(02)",
	ErrNetworkUnreachable:   "Network unreachable(03)",
	ErrHostUnreachable:      "Host unreachable(04)",
	ErrConnectionRefused:    "Connection refused(05)",
	ErrTTLExpired:           "TTL expired(06)",
	ErrCommandNotSupported:  "Command not supported(07)",
	ErrAddressNotSupported:  "Address type not supported(08)",
}

func (se SocksError) Error() string {
	if str, ok := errMap[se]; ok {
		return str
	}
	return "unkonow error"
}

// SOCKS errors as defined in RFC 1928 section 6
const (
	ErrGeneralFailure SocksError = iota + 1
	ErrConnectionNotAllowed
	ErrNetworkUnreachable
	ErrHostUnreachable
	ErrConnectionRefused
	ErrTTLExpired
	ErrCommandNotSupported
	ErrAddressNotSupported
)

// MaxAddrLen is the max size of SOCKS address in bytes:
// ATYP(1) + DST.ADDR(1 + 253) + DST.PORT(2)
const MaxAddrLen = 1 + 1 + 253 + 2

// Addr represents a SOCKS address as defined in RFC 1928 section 5.
type Addr []byte

// String serializes SOCKS address a to string form.
func (a Addr) String() string {
	var host, port string

	switch a[0] { // address type
	case AtypDomainName:
		host = string(a[2 : 2+int(a[1])])
		port = strconv.Itoa((int(a[2+int(a[1])]) << 8) | int(a[2+int(a[1])+1]))
	case AtypIPv4:
		host = net.IP(a[1 : 1+net.IPv4len]).String()
		port = strconv.Itoa((int(a[1+net.IPv4len]) << 8) | int(a[1+net.IPv4len+1]))
	case AtypIPv6:
		host = net.IP(a[1 : 1+net.IPv6len]).String()
		port = strconv.Itoa((int(a[1+net.IPv6len]) << 8) | int(a[1+net.IPv6len+1]))
	}

	return net.JoinHostPort(host, port)
}

func HandShake(conn net.Conn) (Addr, error) {
	buf := make([]byte, MaxAddrLen)

	// read VER, NMETHODS, METHODS
	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return nil, errors.WithStack(err)
	}

	// only handle socks5 protocol
	if buf[0] != 0x05 {
		log.Errorf("server do not support client version:%v", buf[0])
		return nil, errors.WithStack(ErrCommandNotSupported)
	}

	nmethods := buf[1]
	if _, err := io.ReadFull(conn, buf[:nmethods]); err != nil {
		log.Errorf("read methods err: %v, nmethods: %v", err, nmethods)
		return nil, errors.WithStack(err)
	}

	// reply: use socks5 and no authentication required
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return nil, errors.WithStack(err)
	}

	// read VER CMD RSV ATYP DST.ADDR DST.PORT
	if _, err := io.ReadFull(conn, buf[:3]); err != nil {
		return nil, errors.WithStack(err)
	}
	if buf[1] != CmdConnect {
		return nil, errors.WithStack(ErrCommandNotSupported)
	}

	addr, err := readAddr(conn, buf)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	// write VER REP RSV ATYP BND.ADDR BND.PORT
	_, err = conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x08, 0x43})

	return addr, err
}

func readAddr(r io.Reader, buf []byte) (Addr, error) {
	if len(buf) < MaxAddrLen {
		return nil, errors.WithStack(io.ErrShortBuffer)
	}

	// read atyp(1 byte): address type of following address
	if _, err := io.ReadFull(r, buf[:1]); err != nil {
		return nil, errors.WithStack(err)
	}

	switch buf[0] {
	case AtypDomainName:
		// 2nd byte represents domain length
		if _, err := io.ReadFull(r, buf[1:2]); err != nil {
			return nil, errors.WithStack(err)
		}

		_, err := io.ReadFull(r, buf[2:2+int(buf[1])+2])
		return buf[:1+1+int(buf[1])+2], errors.WithStack(err)

	case AtypIPv4:
		_, err := io.ReadFull(r, buf[1:1+net.IPv4len+2])
		return buf[:1+net.IPv4len+2], errors.WithStack(err)

	case AtypIPv6:
		_, err := io.ReadFull(r, buf[1:1+net.IPv6len+2])
		return buf[:1+net.IPv6len+2], errors.WithStack(err)
	}

	return nil, errors.WithStack(ErrAddressNotSupported)
}
