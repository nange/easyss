package easyss_mobile

import (
	"net"
	"os"

	"github.com/nange/easyss/v2/log"
	_ "golang.org/x/mobile/bind"
)

func StartEasyssService(fd int) {
	f := os.NewFile(uintptr(fd), "easytun")
	ln, err := net.FileListener(f)
	if err != nil {
		log.Error("[EASYSS-MOBILE] net.FileListener", "err", err)
		return
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				log.Error("[EASYSS-MOBILE] listener accept", "err", err)
				return
			}
			log.Info("[EASYSS-MOBILE] conn", "local_addr", conn.LocalAddr(), "remote_addr", conn.RemoteAddr())
			_ = conn.Close()
		}
	}()

	log.Info("[EASYSS-MOBILE] net.FileListener success...")
}
