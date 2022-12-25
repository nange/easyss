//go:build with_notray

package main

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/nange/easyss"
	log "github.com/sirupsen/logrus"
)

func StartEasyss(ss *easyss.Easyss) {
	if err := ss.InitTcpPool(); err != nil {
		log.Errorf("init tcp pool error:%v", err)
	}

	go ss.LocalSocks5() // start local server
	go ss.LocalHttp()   // start local http proxy server
	if ss.EnableForwardDNS() {
		go ss.LocalDNSForward() // start local dns forward server
	}

	if ss.EnabledTun2socks() {
		if err := ss.CreateTun2socks(); err != nil {
			log.Fatalf("create tun2socks err:%s", err.Error())
		}
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Kill, os.Interrupt, syscall.SIGINT, syscall.SIGTERM,
		syscall.SIGQUIT)

	select {
	case sig := <-c:
		log.Infof("got signal to exit: %v", sig)
		ss.Close()
		os.Exit(0)
	}
}
