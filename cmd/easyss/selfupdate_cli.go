package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/selfupdate"
	"github.com/nange/easyss/v3/version"
)

// runSelfupdateSubcommand handles the "selfupdate" subcommand (check the
// latest release, and by default download and replace the running binary
// without restarting). It reports whether the subcommand was handled, in
// which case the process has already exited.
func runSelfupdateSubcommand() bool {
	if len(os.Args) < 2 || os.Args[1] != "selfupdate" {
		return false
	}
	os.Exit(runSelfupdate())
	return true
}

// runSelfupdate implements the "selfupdate" subcommand shared by the tray
// and headless client builds. It never starts the proxy or the tray; on a
// successful update the binary has been replaced in place and the user
// restarts the app manually.
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
	product := selfupdateProduct()

	if checkOnly {
		rel, err := selfupdate.CheckCLI(ctx, proxyPort, product)
		if err != nil {
			if errors.Is(err, selfupdate.ErrUpToDate) {
				fmt.Println("已是最新版本:", version.Tag())
				return 0
			}
			log.Error("[EASYSS-V3] selfupdate check", "err", err)
			return 1
		}
		fmt.Printf("发现新版本 %s（当前 %s），执行 %s selfupdate 可升级\n",
			rel.TagName, version.Tag(), filepath.Base(os.Args[0]))
		return 0
	}

	if err := selfupdate.RunCLI(ctx, proxyPort, product); err != nil {
		if errors.Is(err, selfupdate.ErrUpToDate) {
			fmt.Println("已是最新版本:", version.Tag())
			return 0
		}
		log.Error("[EASYSS-V3] selfupdate", "err", err)
		return 1
	}
	fmt.Println("已更新到最新版本，请重启 easyss 完成升级")
	return 0
}
