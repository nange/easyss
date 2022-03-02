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
	log.Infof("on mips arch, we should ignore systray")

	if err := ss.InitTcpPool(); err != nil {
		log.Errorf("init tcp pool error:%v", err)
	}

	go ss.Local()     // start local server
	go ss.HttpLocal() // start local http proxy server

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Kill, os.Interrupt, syscall.SIGINT, syscall.SIGTERM,
		syscall.SIGQUIT)

	log.Infof("got signal to exit: %v", <-c)
}
