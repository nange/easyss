package easyss

import (
	"context"
	_ "embed"
	"errors"
	"os/exec"
	"time"

	"github.com/nange/easyss/util"
	log "github.com/sirupsen/logrus"
	"github.com/xjasonlyu/tun2socks/v2/engine"
)

//go:embed create_tun_dev.sh
var createTunDevSh []byte

//go:embed close_tun_dev.sh
var closeTunDevSh []byte

var (
	tunDevice = "tun-easyss"
)

func (ss *Easyss) CreateTun2socks() error {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	if err := ss.createTunDevAndSetIpRoute(); err != nil {
		log.Errorf("add tun device and set ip-route err:%s", err.Error())
		return err
	}

	key := &engine.Key{
		Proxy:      ss.Socks5ProxyAddr(),
		Device:     tunDevice,
		LogLevel:   "warning",
		UDPTimeout: ss.Timeout(),
	}
	engine.Insert(key)
	engine.Start()

	ss.tun2socksEnabled = true
	log.Infof("tun2socks server and tun device init success")
	return nil
}

func (ss *Easyss) createTunDevAndSetIpRoute() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if ss.ServerIP() == "" {
		return errors.New("server ips is empty")
	}

	namePath, err := util.WriteToTemp("create_tun_dev.sh", createTunDevSh)
	if err != nil {
		log.Errorf("write close_tun_dev.sh to temp file err:%v", err.Error())
		return err
	}

	if err := exec.CommandContext(ctx, "pkexec", "bash",
		namePath, tunDevice, ss.ServerIP(), ss.LocalGateway(), ss.LocalDevice()).Run(); err != nil {
		log.Errorf("exec create_tun_dev.sh err:%s", err.Error())
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
	if err := ss.closeTunDevAndDelIpRoute(); err != nil {
		return err
	}

	ss.tun2socksEnabled = false
	return nil
}

func (ss *Easyss) closeTunDevAndDelIpRoute() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	namePath, err := util.WriteToTemp("close_tun_dev.sh", closeTunDevSh)
	if err != nil {
		log.Errorf("write close_tun_dev.sh to temp file err:%v", err.Error())
		return err
	}

	if err := exec.CommandContext(ctx, "pkexec", "bash",
		namePath, tunDevice, ss.ServerIP(), ss.LocalGateway(), ss.LocalDevice()).Run(); err != nil {
		log.Errorf("exec close_tun_dev.sh err:%s", err.Error())
		return err
	}

	return nil
}
