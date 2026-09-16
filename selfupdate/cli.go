package selfupdate

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/version"
)

// errUpToDate 表示本地构建已与最新 release 一致。
// runCheck 在无需更新时返回该错误。
var errUpToDate = errors.New("already up to date")

// checkCLI 检查给定产品的最新已发布 release：有更新版本时返回它，
// 本地构建已是最新时返回 errUpToDate。它从不下载任何内容。
// proxyPort > 0 时，请求经由本地 easyss HTTP 代理（127.0.0.1:<proxyPort>）转发；
// 否则使用直连。
func checkCLI(ctx context.Context, proxyPort int, product Product) (*Release, error) {
	return runCheck(ctx, NewClient(proxyPort), version.Tag())
}

// runCLI 从命令行对给定产品执行一次性自更新：先检查最新 release，若存在
// 更新版本，则下载发布资产并原地替换正在运行的二进制。它从不重启进程——
// 调用方随后退出，由用户或服务管理器启动新二进制。当本地构建已是最新
// release 时返回 errUpToDate。proxyPort > 0 时，请求经由本地 easyss HTTP
// 代理（127.0.0.1:<proxyPort>）转发；否则使用直连。
func runCLI(ctx context.Context, proxyPort int, product Product) error {
	c := NewClient(proxyPort)
	rel, err := runCheck(ctx, c, version.Tag())
	if err != nil {
		return err
	}
	log.Info("[SELFUPDATE] downloading and installing", "product", product, "version", rel.TagName)
	if err := updateFor(ctx, c, product, rel); err != nil {
		return fmt.Errorf("update to %s: %w", rel.TagName, err)
	}
	return nil
}

// RunCLICommand 为给定产品运行 "selfupdate" 子命令：解析 --check/--proxy-port，
// 在 --help/--h 时打印子命令帮助，并返回进程退出码（0 = 成功或已显示帮助，
// 1 = 失败，2 = 参数错误）。它从不重启进程；调用方随后退出，
// 由用户或服务管理器启动新二进制。
func RunCLICommand(args []string, product Product) int {
	fs := flag.NewFlagSet("selfupdate", flag.ContinueOnError)
	var proxyPort int
	var checkOnly bool
	fs.IntVar(&proxyPort, "proxy-port", 0, "route fetches through the local easyss HTTP proxy at 127.0.0.1:<port>")
	fs.BoolVar(&checkOnly, "check", false, "only check whether a new version is available, do not download")
	fs.Usage = func() {
		out := fs.Output()
		_, _ = fmt.Fprintf(out, "用法: %s selfupdate [flags]\n\n", filepath.Base(os.Args[0]))
		_, _ = fmt.Fprintf(out, "从 GitHub 检查 %s 的最新 release；默认下载对应平台的发布包并原地替换当前二进制\n", product)
		_, _ = fmt.Fprintf(out, "（不自动重启）。更新完成后请手动重启进程（或由 systemd/supervisor 自动拉起）\n使新版本生效。\n\nFlags:\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}

	ctx, cancel := context.WithTimeout(context.Background(), CheckTimeout)
	defer cancel()
	bin := filepath.Base(os.Args[0])

	if checkOnly {
		rel, err := checkCLI(ctx, proxyPort, product)
		if err != nil {
			if errors.Is(err, errUpToDate) {
				fmt.Println("已是最新版本:", version.Tag())
				return 0
			}
			log.Error("[SELFUPDATE] selfupdate check", "err", err)
			return 1
		}
		fmt.Printf("发现新版本 %s（当前 %s），执行 %s selfupdate 可升级\n",
			rel.TagName, version.Tag(), bin)
		return 0
	}

	if err := runCLI(ctx, proxyPort, product); err != nil {
		if errors.Is(err, errUpToDate) {
			fmt.Println("已是最新版本:", version.Tag())
			return 0
		}
		log.Error("[SELFUPDATE] selfupdate", "err", err)
		return 1
	}
	fmt.Printf("已更新到最新版本，请重启 %s 完成升级\n", bin)
	return 0
}

// runCheck 获取最新 release，并报告 currentTag 是否落后于它。
// 整个检查过程应用 CheckTimeout 超时。
func runCheck(ctx context.Context, c *Client, currentTag string) (*Release, error) {
	checkCtx, cancel := context.WithTimeout(ctx, CheckTimeout)
	defer cancel()

	rel, err := CheckLatest(checkCtx, c)
	if err != nil {
		return nil, fmt.Errorf("check latest release: %w", err)
	}
	if !HasNewVersion(currentTag, rel.TagName) {
		return nil, errUpToDate
	}
	return rel, nil
}
