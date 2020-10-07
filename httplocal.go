package easyss

import (
	"fmt"
	"net/http"

	"github.com/nange/httpproxy"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

func (ss *Easyss) HttpLocal() error {
	httpPort := ss.config.LocalPort + 1000
	log.Infof("starting http local proxy server :%d", httpPort)
	prx, err := httpproxy.NewProxy()
	if err != nil {
		log.Errorf("new http proxy err:%+v", errors.WithStack(err))
		return err
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

	if err := http.ListenAndServe(fmt.Sprintf(":%d", httpPort), prx); err != nil {
		log.Errorf("http server start err:%+v", errors.WithStack(err))
		return err
	}

	return nil
}
