package easyss_mobile

import (
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/Kr328/tun2socket"
	"github.com/cespare/xxhash/v2"
	"github.com/nange/easyss/v2"
	"github.com/nange/easyss/v2/log"
	"github.com/patrickmn/go-cache"
	"github.com/txthinking/socks5"
	"github.com/xjasonlyu/tun2socks/v2/engine"
	_ "golang.org/x/mobile/bind"
)

var easyService *easyss.Easyss
var udpExchCache = cache.New(cache.NoExpiration, cache.NoExpiration)

func StartEasyssService(fd int32, proxyAddr, server, serverPort, password, method, proxyRule, outboundProto, logLevel, caPath string) {
	//startTun2socksEngineForAndroid(fd, proxyAddr)

	config := &easyss.Config{}
	config.Server = server
	sp, _ := strconv.ParseInt(serverPort, 10, 64)
	config.ServerPort = int(sp)
	config.Password = password
	config.Method = method
	config.ProxyRule = proxyRule
	config.OutboundProto = outboundProto
	config.LogLevel = logLevel
	config.CAPath = caPath
	config.SetDefaultValue()

	easyService, _ = easyss.New(config)
	startEasyss(easyService)

	time.Sleep(time.Second)

	systemTun(fd)

	log.Info("[EASYSS-MOBILE] net.FileListener success...")
}

func startTun2socksEngineForAndroid(fd int32, proxyAddr string) {
	device := fmt.Sprintf("fd://%d", fd)
	key := &engine.Key{
		Proxy:                proxyAddr,
		Device:               device,
		LogLevel:             "error",
		TCPSendBufferSize:    easyss.RelayBufferSizeString,
		TCPReceiveBufferSize: easyss.RelayBufferSizeString,
		UDPTimeout:           60 * time.Second,
	}
	engine.Insert(key)
	engine.Start()
}

func startEasyss(ss *easyss.Easyss) {
	if err := ss.InitTcpPool(); err != nil {
		log.Error("[EASYSS-MOBILE] init tcp pool", "err", err)
	}

	go ss.LocalSocks5() // start local server
}

const (
	TunSubnetPrefix = 16
	TunGateway      = "198.18.0.1"
	TunPortal       = "198.18.0.2"
)

func systemTun(fd int32) {
	rwc := os.NewFile(uintptr(fd), "/dev/tun")
	addr, err := netip.ParsePrefix(fmt.Sprintf("%s/%d", TunGateway, TunSubnetPrefix))
	if err != nil {
		log.Error("[EASYSS-MOBILE] netip.ParsePrefix", "err", err)
		return
	}
	portal := netip.MustParseAddr(TunPortal)
	tunSocket, err := tun2socket.StartTun2Socket(rwc, addr, portal)
	if err != nil {
		log.Error("[EASYSS-MOBILE] StartTun2Socket", "err", err)
		return
	}

	// TCP:
	go handleTCP(tunSocket)
	// UDP:
	go handleUDP(tunSocket)
}

func handleTCP(tunSocket *tun2socket.Tun2Socket) {
	tcp := tunSocket.TCP()
	defer tcp.Close()

	client, err := socks5.NewClient("127.0.0.1:2080", "", "", 0, 600)
	if err != nil {
		log.Error("[EASYSS-MOBILE] socks5.NewClient", "err", err)
		return
	}
	defer client.Close()

	for {
		log.Info("[EASYSS-MOBILE] starting accept TCP connection============")
		conn, err := tcp.Accept()
		if err != nil {
			log.Error("[EASYSS-MOBILE] tcp.Accept", "err", err)
			return
		}
		log.Info("[EASYSS-MOBILE] TCP Accept Conn===================", "local_addr", conn.LocalAddr().String(), "remote_addr", conn.RemoteAddr().String())
		conn2, err := client.Dial("tcp", conn.RemoteAddr().String())
		if err != nil {
			log.Error("[EASYSS-MOBILE] TCP client.Dial", "err", err)
			return
		}

		go handleTCPRelay(conn, conn2)
	}
}

func handleTCPRelay(conn, conn2 net.Conn) {
	defer conn.Close()
	defer conn2.Close()

	wg := &sync.WaitGroup{}
	wg.Add(2)
	go func() {
		defer wg.Done()

		_, err := io.Copy(conn2, conn)
		if err != nil {
			log.Warn("[EASYSS-MOBILE] copy conn to conn2", "err", err)
		}
		_ = easyss.CloseWrite(conn2)
	}()
	go func() {
		defer wg.Done()

		_, err := io.Copy(conn, conn2)
		if err != nil {
			log.Warn("[EASYSS-MOBILE] copy conn2 to conn", "err", err)
		}
		_ = easyss.CloseWrite(conn)
	}()
	wg.Wait()

	log.Info("[EASYSS-MOBILE] copy between conn and conn2 completed...................",
		"conn.LocalAddr", conn.LocalAddr().String(), "conn2.LocalAddr", conn2.LocalAddr().String())
}

func handleUDP(tunSocket *tun2socket.Tun2Socket) {
	udp := tunSocket.UDP()
	defer udp.Close()

	client, err := socks5.NewClient("127.0.0.1:2080", "", "", 0, 60)
	if err != nil {
		log.Error("[EASYSS-MOBILE] socks5.NewClient", "err", err)
		return
	}
	defer client.Close()

	buf := make([]byte, 65535)
	send := func(ue *easyss.UDPExchange, data []byte) error {
		_, err := ue.RemoteConn.Write(data)
		if err != nil {
			return err
		}

		return nil
	}

	for {
		n, source, dest, err := udp.ReadFrom(buf)
		if err != nil {
			log.Error("[EASYSS-MOBILE] udp.ReadFrom break", "err", err)
			break
		}
		if n <= 0 {
			log.Info("UDP Conn read failed=========", "n", n, "err", err, "source", source.String(), "dest", dest.String())
			continue
		}

		var ue *easyss.UDPExchange
		var exchKey = source.String() + dest.String()
		iue, ok := udpExchCache.Get(exchKey)
		if ok {
			ue = iue.(*easyss.UDPExchange)
			if err := send(ue, buf[:n]); err != nil {
				log.Error("[EASYSS-MOBILE] UDP send to socks5", "err", err)
			}
			continue
		}

		conn, err := client.Dial("udp", dest.String())
		if err != nil {
			log.Error("[EASYSS-MOBILE] UDP client.Dial", "err", err)
			return
		}

		sAddr, _ := net.ResolveUDPAddr("udp", source.String())
		ue = &easyss.UDPExchange{
			ClientAddr: sAddr,
			RemoteConn: conn,
		}
		if err := send(ue, buf[:n]); err != nil {
			log.Error("[EASYSS-MOBILE] send data to socks5", "err", err)
			return
		}
		udpExchCache.Set(exchKey, ue, -1)

		// read from socks5, and write back to tun
		go func() {
			buf := make([]byte, 65535)
			defer func() {
				udpExchCache.Delete(exchKey)
				ue.RemoteConn.Close()
			}()

			for {
				n, err := ue.RemoteConn.Read(buf)
				if err != nil {
					log.Error("[EASYSS-MOBILE] UDP read from socks5", "err", err)
					return
				}

				if n > 0 {
					log.Info("[EASYSS-MOBILE] UDP read from socks5 and write back to device",
						"len", n, "dest", dest.String(), "source", source.String())
					if _, err := udp.WriteTo(buf[:n], dest, source); err != nil {
						log.Error("[EASYSS-MOBILE] UDP write back to tun", "err", err)
						return
					}
				}
			}
		}()
	}
}

var udpLocks [easyss.UDPLocksCount]sync.Mutex

func lockKey(key string) {
	hashVal := xxhash.Sum64String(key)
	lockID := hashVal & easyss.UDPLocksAndOpVal
	udpLocks[lockID].Lock()
}

func unlockKey(key string) {
	hashVal := xxhash.Sum64String(key)
	lockID := hashVal & easyss.UDPLocksAndOpVal
	udpLocks[lockID].Unlock()
}
