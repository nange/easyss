//go:build darwin

package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"time"

	"github.com/nange/easyss/v3/client"
	"github.com/nange/easyss/v3/client/config"
	"github.com/nange/easyss/v3/client/proxy"
	"github.com/nange/easyss/v3/client/tun"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/protocol"
	"github.com/nange/easyss/v3/util"
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

	// Use the direct dialer (bind to physical interface) to prevent transport
	// connections from being captured by the TUN device this process manages.
	cfg.Local.EnableTun2socks = true

	// Create client with transport for ICMP proxying through the Easyss server.
	cli, err := client.New(cfg)
	if err != nil {
		log.Error("[TUN-ONLY] create client", "err", err)
		os.Exit(1)
	}
	defer cli.Close() //nolint:errcheck

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

	// Resolve server IPs and add bypass routes before starting TUN.
	// This ensures the transport connection to the Easyss server bypasses the
	// TUN device, preventing a routing loop.
	serverIPs := resolveServerIPs(cfg)
	gw, _, _ := util.SysGatewayAndDevice()
	gwV6, _, _ := util.SysGatewayAndDeviceV6()
	addServerBypassRoutes(serverIPs, gw, gwV6)
	defer removeServerBypassRoutes(serverIPs, gw, gwV6)

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

// resolveServerIPs resolves all server addresses from the config to IPv4 and IPv6 IPs.
func resolveServerIPs(cfg *config.ClientConfig) (ips []net.IP) {
	svr := cfg.DefaultServer()
	if svr == nil {
		return nil
	}
	parsed := net.ParseIP(svr.Address)
	if parsed != nil {
		return []net.IP{parsed}
	}

	// Hostname — resolve both v4 and v6.
	addrs, err := net.LookupHost(svr.Address)
	if err != nil {
		log.Warn("[TUN-ONLY] resolve server ip", "addr", svr.Address, "err", err)
		return nil
	}
	for _, a := range addrs {
		ips = append(ips, net.ParseIP(a))
	}
	return ips
}

// addServerBypassRoutes adds host routes for the server IPs through the
// physical gateway to prevent them from being captured by the TUN device.
func addServerBypassRoutes(ips []net.IP, gw, gwV6 string) {
	for _, ip := range ips {
		if ip == nil {
			continue
		}
		if ip.To4() != nil {
			if gw != "" {
				exec.Command("route", "add", "-host", ip.String(), gw).Run() //nolint:errcheck
			}
		} else {
			if gwV6 != "" {
				exec.Command("route", "add", "-inet6", "-host", ip.String(), gwV6).Run() //nolint:errcheck
			}
		}
	}
}

// removeServerBypassRoutes removes the host routes added by addServerBypassRoutes.
func removeServerBypassRoutes(ips []net.IP, gw, gwV6 string) {
	for _, ip := range ips {
		if ip == nil {
			continue
		}
		if ip.To4() != nil {
			if gw != "" {
				exec.Command("route", "delete", "-host", ip.String(), gw).Run() //nolint:errcheck
			}
		} else {
			if gwV6 != "" {
				exec.Command("route", "delete", "-inet6", "-host", ip.String(), gwV6).Run() //nolint:errcheck
			}
		}
	}
}
