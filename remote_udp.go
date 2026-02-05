package easyss

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/nange/easyss/v2/cipherstream"
	"github.com/nange/easyss/v2/log"
	"github.com/nange/easyss/v2/util/bytespool"
	"github.com/nange/easyss/v2/util/netpipe"
	"github.com/negrel/conc"
)

func (es *EasyServer) remoteUDPHandle(conn net.Conn, addrStr, method string, isDNSProto, tryReuse bool) error {
	uConn, err := es.targetConn("udp", addrStr)
	if err != nil {
		return fmt.Errorf("net.DialUDP %v err:%v", addrStr, err)
	}

	csStream, err := cipherstream.New(conn, es.Password(), method, cipherstream.FrameTypeData, cipherstream.FlagUDP)
	if err != nil {
		return fmt.Errorf("new cipherstream err:%v, method:%v", err, method)
	}

	_ = csStream.SetDeadline(time.Now().Add(es.MaxConnWaitTimeout()))
	defer func() {
		_ = csStream.SetDeadline(time.Time{})
		csStream.(*cipherstream.CipherStream).Release()
	}()

	var _tryReuse bool

	jobs := []conc.Job[struct{}]{
		// send
		func(_ context.Context) (struct{}, error) {
			var buf = bytespool.Get(MaxUDPDataSize)
			defer bytespool.MustPut(buf)
			for {
				n, err := csStream.Read(buf[:])
				if err != nil {
					if errors.Is(err, cipherstream.ErrFINRSTStream) {
						_tryReuse = true
						log.Debug("[REMOTE_UDP] received FIN when reading data from client, try to reuse the connection")
					} else if !errors.Is(err, io.EOF) && !errors.Is(err, netpipe.ErrReadDeadline) && !errors.Is(err, netpipe.ErrPipeClosed) {
						log.Warn("[REMOTE_UDP] read data from client connection", "err", err)
					}
					// nolint:errcheck
					uConn.Close()
					return struct{}{}, nil
				}
				if isDNSProto {
					// try to parse the dns request
					msg := &dns.Msg{}
					if err := msg.Unpack(buf[:n]); err == nil {
						log.Info("[REMOTE_UDP] doing dns request for", "target", msg.Question[0].Name)
					}
				}
				_, err = uConn.Write(buf[:n])
				if err != nil {
					log.Error("[REMOTE_UDP] write data to remote connection", "err", err)
					return struct{}{}, nil
				}
				_ = csStream.SetDeadline(time.Now().Add(es.MaxConnWaitTimeout()))
			}
		},
		// receive
		func(_ context.Context) (struct{}, error) {
			var buf = bytespool.Get(MaxUDPDataSize)
			defer bytespool.MustPut(buf)
			for {
				n, err := uConn.Read(buf[:])
				if err != nil {
					log.Debug("[REMOTE_UDP] read data from remote connection", "err", err)
					return struct{}{}, nil
				}

				if isDNSProto {
					msg := &dns.Msg{}
					if err = msg.Unpack(buf[:n]); err == nil && len(msg.Question) > 0 {
						domain := msg.Question[0].Name
						domain = strings.TrimSuffix(domain, ".")

						isNextProxyDomain := false
						es.nextProxyMu.RLock()
						if _, ok := es.nextProxyDomains[domain]; ok {
							isNextProxyDomain = true
						} else {
							subs := subDomains(domain)
							for _, sub := range subs {
								if _, ok := es.nextProxyDomains[sub]; ok {
									isNextProxyDomain = true
									break
								}
							}
						}
						es.nextProxyMu.RUnlock()

						if isNextProxyDomain {
							for _, ans := range msg.Answer {
								if a, ok := ans.(*dns.A); ok {
									es.SetNextProxyIP(a.A.String())
									log.Info("[REMOTE_UDP] update next proxy ip", "domain", domain, "ip", a.A.String())
								}
							}
						}
					}
				}

				_, err = csStream.Write(buf[:n])
				if err != nil {
					log.Error("[REMOTE_UDP] write data to tcp connection", "err", err)
					return struct{}{}, nil
				}
				_ = csStream.SetDeadline(time.Now().Add(es.MaxConnWaitTimeout()))
			}
		},
	}

	_, _ = conc.All(jobs)

	var reuse error
	if tryReuse && _tryReuse {
		log.Debug("[REMOTE_UDP] request is finished, try to reuse underlying tcp connection")
		reuse = tryReuseInServer(csStream, es.Timeout())
	}

	if reuse != nil {
		log.Warn("[REMOTE_UDP] underlying proxy connection is unhealthy, need close it", "reuse", reuse)
		return reuse
	} else {
		log.Debug("[REMOTE_UDP] underlying proxy connection is healthy, so reuse it")
	}

	return nil
}

func tryReuseInServer(cipher net.Conn, timeout time.Duration) error {
	if err := cipher.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}
	if err := WriteACKToCipher(cipher); err != nil {
		return err
	}
	if err := CloseWrite(cipher); err != nil {
		return err
	}
	if err := ReadACKFromCipher(cipher); err != nil {
		return err
	}
	if err := cipher.SetReadDeadline(time.Time{}); err != nil {
		return err
	}

	return nil
}
