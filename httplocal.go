package easyss

import (
	"net/http"

	"github.com/nange/httpproxy"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

func (ss *Easyss) HttpLocal() {
	log.Infof("starting http local proxy server :8080")
	prx, err := httpproxy.NewProxy()
	if err != nil {
		log.Errorf("new http proxy err:%+v", errors.WithStack(err))
		return
	}

	onForward := func(ctx *httpproxy.Context, host string) error {
		hijConn, err := ctx.GetHijConn()
		if err != nil {
			log.Errorf("get hijack conn, err:%+v", errors.WithStack(err))
			return err
		}
		if _, err := hijConn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n")); err != nil {
			log.Errorf("write hijack ok err:%+v", errors.WithStack(err))
			hijConn.Close()
			return err
		}
		return ss.localRelay(hijConn, host)
	}
	prx.OnForward = onForward

	if err := http.ListenAndServe(":8080", prx); err != nil {
		log.Errorf("http server start err:%+v", errors.WithStack(err))
	}
}
