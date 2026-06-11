//go:build !without_tray

package main

import (
	"fmt"

	"github.com/wzshiming/sysproxy"
)

func setSysProxy(httpPort int) error {
	addr := fmt.Sprintf("127.0.0.1:%d", httpPort)
	return sysproxy.OnHTTP(addr)
}

func unsetSysProxy() error {
	return sysproxy.OffHTTP()
}
