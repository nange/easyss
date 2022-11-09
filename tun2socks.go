package easyss

import (
	"context"
	"errors"
	"os/exec"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/xjasonlyu/tun2socks/v2/engine"
)

var (
	tunDevice = "tun-easyss"
	tunIP     = "198.18.0.1"
	tunMask   = "/15"
)

func (ss *Easyss) InitTun2socks() error {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	key := &engine.Key{
		MTU:        1500,
		Proxy:      ss.Socks5ProxyAddr(),
		Device:     tunDevice,
		LogLevel:   "info",
		UDPTimeout: ss.Timeout(),
	}
	engine.Insert(key)
	engine.Start()

	if err := ss.addTunDevAndSetIpRoute(); err != nil {
		log.Errorf("add tun device and set ip-route err:%s", err.Error())
		return err
	}
	ss.tun2socksEnabled = true
	log.Infof("tun2socks server and tun device init success")
	return nil
}

func (ss *Easyss) addTunDevAndSetIpRoute() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if ss.ServerIP() == "" {
		return errors.New("server ips is empty")
	}

	err := exec.CommandContext(ctx, "sudo",
		"ip", "addr", "add", tunIP+tunMask, "dev", tunDevice).Run()
	if err != nil {
		log.Errorf("set ip for tun device err:%s", err.Error())
		return err
	}

	err = exec.CommandContext(ctx, "sudo",
		"ip", "link", "set", "dev", tunDevice, "up").Run()
	if err != nil {
		log.Errorf("set tun device up err:%s", err.Error())
		return err
	}

	err = exec.CommandContext(ctx, "sudo",
		"ip", "route", "add", ss.ServerIP(), "via", ss.LocalGateway(), "dev", ss.LocalDevice()).Run()
	if err != nil {
		log.Errorf("set server ip-route err:%s", err.Error())
		return err
	}

	err = exec.CommandContext(ctx, "sudo",
		"ip", "route", "add", "default", "via", tunIP, "dev", tunDevice, "metric", "1").Run()
	if err != nil {
		log.Errorf("add default ip-route to tun device err:%s", err.Error())
		return err
	}

	return nil
}

func (ss *Easyss) CloseTun2socks() error {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	return ss.closeTun2socks()
}

func (ss *Easyss) closeTun2socks() error {
	engine.Stop()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := exec.CommandContext(ctx, "sudo",
		"ip", "route", "del", ss.ServerIP(), "via", ss.LocalGateway(), "dev", ss.LocalDevice()).Run()
	if err != nil {
		log.Errorf("delete server ip-route err:%s", err.Error())
		return err
	}
	ss.tun2socksEnabled = false
	return nil
}
