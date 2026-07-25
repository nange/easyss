//go:build darwin

package main

import (
	"fmt"
	"os"
	"time"

	"github.com/nange/easyss/v3/client"
	"github.com/nange/easyss/v3/client/config"
	"github.com/nange/easyss/v3/client/proxy"
	"github.com/nange/easyss/v3/client/tun"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/protocol"
)

// runTunOnly starts a minimal TUN manager as root (launched by the non-root tray process).
// It monitors the keepalive file; when the file is removed, it performs a clean shutdown.
func runTunOnly(cfg *config.ClientConfig, keepaliveFile string) {
	log.Info("[TUN-ONLY] starting tun-only helper")

	if err := os.WriteFile(keepaliveFile, nil, 0644); err != nil {
		log.Error("[TUN-ONLY] write keepalive", "err", err)
		os.Exit(1)
	}
	defer os.Remove(keepaliveFile) //nolint:errcheck

	// Create client with transport for ICMP proxying through the Easyss server.
	cli, err := client.New(cfg)
	if err != nil {
		log.Error("[TUN-ONLY] create client", "err", err)
		os.Exit(1)
	}
	_ = cli.Close()

	method := protocol.MethodFromString(cfg.DefaultServer().Method)
	if method == 0 {
		method = protocol.MethodAES256GCM
	}

	// Create stream handler for ICMP proxying (UDP_PROXY is handled by the
	// tun2socks engine via the SOCKS5 proxy; only ICMP needs its own transport).
	streamHandler := proxy.NewStreamHandler(
		cli.Transport(),
		cli.MasterKey(),
		cli.ShaperConfig(),
		10*cfg.TimeoutDuration(),
	)

	socksProxyAddr := fmt.Sprintf("socks5://127.0.0.1:%d", cfg.Local.SocksPort)
	tunCfg := tun.Config{
		Socks5Addr: socksProxyAddr,
		DNSServer:  config.DefaultSystemDNS,
	}
	if ipv6 := cli.Router().ServerIPV6(); ipv6 != "" {
		tunCfg.ServerIPV6 = ipv6
	}

	tunMgr := tun.New(tunCfg)

	icmpHandler := tun.NewICMPHandler(cli.Router())
	icmpHandler.SetProxy(streamHandler, method)

	if err := tunMgr.Start(icmpHandler); err != nil {
		log.Error("[TUN-ONLY] start tun manager", "err", err)
		os.Exit(1)
	}
	defer tunMgr.Stop()

	log.Info("[TUN-ONLY] tun manager started")

	// Monitor the keepalive file. The non-root tray process removes it
	// to signal that TUN should be disabled.
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		if _, err := os.Stat(keepaliveFile); os.IsNotExist(err) {
			log.Info("[TUN-ONLY] keepalive removed, shutting down")
			return
		}
	}
}
