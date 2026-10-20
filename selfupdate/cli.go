package selfupdate

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/version"
)

// errUpToDate 表示本地构建已与最新 release 一致，runCheck 在无需更新时返回它。
var errUpToDate = errors.New("already up to date")

// checkCLI 检查 release：wantTag 为空时找最新 release，存在更新版本才返回；非空时返回该 tag
// 的 release，刻意不与本地版本比较（可重装或回退）。它从不下载。
func checkCLI(ctx context.Context, proxyPort int, wantTag string) (*Release, error) {
	c := NewClient(proxyPort)
	defer c.Close()
	return resolveRelease(ctx, c, version.Tag(), wantTag)
}

// runCLI 从命令行执行一次性自更新：确定目标 release 后下载资产并原地替换二进制，从不重启进程。
func runCLI(ctx context.Context, proxyPort int, product Product, wantTag string) error {
	c := NewClient(proxyPort)
	defer c.Close()
	rel, err := resolveRelease(ctx, c, version.Tag(), wantTag)
	if err != nil {
		return err
	}
	log.Info("[SELFUPDATE] downloading and installing", "product", product,
		"version", rel.TagName, "current", version.Tag(), "requested", wantTag != "")
	if err := updateFor(ctx, c, product, rel); err != nil {
		return fmt.Errorf("update to %s: %w", rel.TagName, err)
	}
	return nil
}

// RunCLICommand 运行 selfupdate 子命令并返回进程退出码（0 成功或已显示帮助，1 失败，2 参数错误）。
func RunCLICommand(args []string, product Product) int {
	fs := flag.NewFlagSet("selfupdate", flag.ContinueOnError)
	var proxyPort int
	var checkOnly bool
	var wantTag string
	fs.IntVar(&proxyPort, "proxy-port", 0, "route fetches through the local easyss HTTP proxy at 127.0.0.1:<port>")
	fs.BoolVar(&checkOnly, "check", false, "only check whether a new version is available, do not download")
	fs.StringVar(&wantTag, "version", "",
		"install a specific release tag (e.g. v3.0.0) instead of the latest release; the tag must match exactly")
	fs.Usage = func() {
		out := fs.Output()
		_, _ = fmt.Fprintf(out, "用法: %s selfupdate [flags]\n\n", filepath.Base(os.Args[0]))
		_, _ = fmt.Fprintf(out, "从 GitHub 检查 %s 的最新 release；默认下载对应平台的发布包并原地替换当前二进制\n", product)
		_, _ = fmt.Fprintf(out, "（不自动重启）。更新完成后请手动重启进程（或由 systemd/supervisor 自动拉起）\n使新版本生效。\n\n--version <tag> 指定具体版本（tag 需与 release tag 完全一致），此时不与本地版本\n比较，因此可以重装当前版本或回退到旧版本。\n\nFlags:\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	// 版本只能通过 --version 指定：静默忽略位置参数会让 "selfupdate v3.0.0"
	// 变成一次意外的升级到最新操作。
	if fs.NArg() > 0 {
		_, _ = fmt.Fprintf(fs.Output(), "意外的参数 %q：指定版本请使用 --version <tag>\n", fs.Arg(0))
		return 2
	}
	wantTag = strings.TrimSpace(wantTag)

	// 不套外层超时：检查阶段由 runCheck/checkTagRelease 施加 CheckTimeout，下载阶段由
	// updateFor 施加 DownloadTimeout，外层预算会覆盖后者，让较慢的下载必然失败。
	ctx := context.Background()
	bin := filepath.Base(os.Args[0])

	if checkOnly {
		rel, err := checkCLI(ctx, proxyPort, wantTag)
		if err != nil {
			if errors.Is(err, errUpToDate) {
				fmt.Println("已是最新版本:", version.Tag())
				return 0
			}
			reportVersionError(err, wantTag)
			log.Error("[SELFUPDATE] selfupdate check", "err", err)
			return 1
		}
		if wantTag != "" {
			return reportTagAvailability(rel, product, bin)
		}
		fmt.Printf("发现新版本 %s（当前 %s），执行 %s selfupdate 可升级\n",
			rel.TagName, version.Tag(), bin)
		return 0
	}

	if err := runCLI(ctx, proxyPort, product, wantTag); err != nil {
		if errors.Is(err, errUpToDate) {
			fmt.Println("已是最新版本:", version.Tag())
			return 0
		}
		reportVersionError(err, wantTag)
		log.Error("[SELFUPDATE] selfupdate", "err", err)
		return 1
	}
	if wantTag != "" {
		fmt.Printf("已更新到指定版本 %s，请重启 %s 完成升级\n", wantTag, bin)
		return 0
	}
	fmt.Printf("已更新到最新版本，请重启 %s 完成升级\n", bin)
	return 0
}

// reportTagAvailability 报告显式指定的版本能否在当前平台安装：release 存在且带有匹配当前产品与
// GOOS/GOARCH 的资产时返回 0，否则返回 1。
func reportTagAvailability(rel *Release, product Product, bin string) int {
	if a := pickAssetFor(rel, product, runtime.GOOS, runtime.GOARCH); a == nil {
		fmt.Printf("版本 %s 存在，但没有 %s/%s 的发布资产（%s）\n",
			rel.TagName, runtime.GOOS, runtime.GOARCH, product.assetName(runtime.GOOS, runtime.GOARCH))
		return 1
	}
	fmt.Printf("版本 %s 可用于当前平台，执行 %s selfupdate --version %s 可安装\n",
		rel.TagName, bin, rel.TagName)
	return 0
}

// reportVersionError 在显式指定版本却查不到 release 时打印一行中文提示，未指定版本时不打印。
func reportVersionError(err error, wantTag string) {
	if wantTag == "" || !errors.Is(err, errReleaseNotFound) {
		return
	}
	fmt.Fprintf(os.Stderr, "未找到版本 %q 对应的 release；tag 需与 release tag 完全一致（例如 v3.0.0）\n", wantTag)
}

// runCheck 获取最新 release 并判断 currentTag 是否落后，全程应用 CheckTimeout。
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

// checkTagRelease 获取指定 tag 的 release，全程应用 CheckTimeout。
func checkTagRelease(ctx context.Context, c *Client, tag string) (*Release, error) {
	checkCtx, cancel := context.WithTimeout(ctx, CheckTimeout)
	defer cancel()

	rel, err := checkTag(checkCtx, c, tag)
	if err != nil {
		return nil, fmt.Errorf("check release %s: %w", tag, err)
	}
	return rel, nil
}

// resolveRelease 返回本次要安装的 release。显式指定 wantTag 时路径上永不适用 errUpToDate：
// 用户可能正是在重装当前版本或回退到更旧的版本。
func resolveRelease(ctx context.Context, c *Client, currentTag, wantTag string) (*Release, error) {
	if wantTag == "" {
		return runCheck(ctx, c, currentTag)
	}
	return checkTagRelease(ctx, c, wantTag)
}
