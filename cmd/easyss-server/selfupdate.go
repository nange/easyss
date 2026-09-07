package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/selfupdate"
	"github.com/nange/easyss/v3/version"
)

// runSelfupdate implements the "selfupdate" subcommand: check the latest
// release and, by default, download and replace the server binary in place
// without restarting. The service manager (or the user) starts the new
// binary afterwards.
func runSelfupdate() int {
	fs := flag.NewFlagSet("selfupdate", flag.ContinueOnError)
	var proxyPort int
	var checkOnly bool
	fs.IntVar(&proxyPort, "proxy-port", 0, "route fetches through the local easyss HTTP proxy at 127.0.0.1:<port>")
	fs.BoolVar(&checkOnly, "check", false, "only check whether a new version is available, do not download")
	if err := fs.Parse(os.Args[2:]); err != nil {
		return 2
	}

	ctx, cancel := context.WithTimeout(context.Background(), selfupdate.CheckTimeout)
	defer cancel()

	if checkOnly {
		rel, err := selfupdate.CheckCLI(ctx, proxyPort, selfupdate.ProductServer)
		if err != nil {
			if errors.Is(err, selfupdate.ErrUpToDate) {
				fmt.Println("已是最新版本:", version.Tag())
				return 0
			}
			log.Error("[EASYSS-SERVER-V3] selfupdate check", "err", err)
			return 1
		}
		fmt.Printf("发现新版本 %s（当前 %s），执行 easyss-server selfupdate 可升级\n",
			rel.TagName, version.Tag())
		return 0
	}

	if err := selfupdate.RunCLI(ctx, proxyPort, selfupdate.ProductServer); err != nil {
		if errors.Is(err, selfupdate.ErrUpToDate) {
			fmt.Println("已是最新版本:", version.Tag())
			return 0
		}
		log.Error("[EASYSS-SERVER-V3] selfupdate", "err", err)
		return 1
	}
	fmt.Println("已更新到最新版本，请重启 easyss-server 完成升级")
	return 0
}
