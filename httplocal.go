package easyss

import (
	"net/http"
	"strconv"

	"github.com/nange/httpproxy"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

func (ss *Easyss) LocalHttp() error {
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

	var addr string
	if ss.BindAll() {
		addr = ":" + strconv.Itoa(ss.LocalHttpProxyPort())
	} else {
		addr = "127.0.0.1:" + strconv.Itoa(ss.LocalHttpProxyPort())
	}
	log.Infof("starting http server at :%v", addr)

	server := &http.Server{Addr: addr, Handler: prx}
	ss.SetHttpProxyServer(server)

	log.Warnf("local http proxy server:%s", server.ListenAndServe())

	return nil
}
