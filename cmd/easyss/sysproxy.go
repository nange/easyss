//go:build !without_tray

package main

import (
	"fmt"
	"strconv"

	"github.com/nange/easyss/v3/log"
	"github.com/wzshiming/sysproxy"
)

func setSysProxy(port int) error {
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	if err := sysproxy.OnHTTP(addr); err != nil {
		return fmt.Errorf("set http proxy: %w", err)
	}
	if err := sysproxy.OnHTTPS(addr); err != nil {
		return fmt.Errorf("set https proxy: %w", err)
	}
	log.Info("[SYSPROXY] proxy enabled", "port", strconv.Itoa(port))
	return nil
}

func unsetSysProxy() error {
	if err := sysproxy.OffHTTP(); err != nil {
		return fmt.Errorf("unset http proxy: %w", err)
	}
	if err := sysproxy.OffHTTPS(); err != nil {
		return fmt.Errorf("unset https proxy: %w", err)
	}
	log.Info("[SYSPROXY] proxy disabled")
	return nil
}
