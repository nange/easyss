//go:build with_notray

package main

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/nange/easyss/v2"
	log "github.com/sirupsen/logrus"
)

func Start(ss *easyss.Easyss) {
	if err := ss.InitTcpPool(); err != nil {
		log.Errorf("[EASYSS-MAIN] init tcp pool error:%v", err)
	}

	go ss.LocalSocks5() // start local server
	go ss.LocalHttp()   // start local http proxy server
	if ss.EnableForwardDNS() {
		go ss.LocalDNSForward() // start local dns forward server
	}

	if ss.EnabledTun2socksFromConfig() {
		if err := ss.CreateTun2socks(); err != nil {
			log.Fatalf("[EASYSS-MAIN] create tun2socks err:%s", err.Error())
		}
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGINT, syscall.SIGTERM,
		syscall.SIGQUIT)

	log.Infof("[EASYSS-MAIN] got signal to exit: %v", <-c)
	ss.Close()
	os.Exit(0)
}
