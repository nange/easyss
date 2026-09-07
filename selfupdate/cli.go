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

// ErrUpToDate reports that the local build already matches the latest
// release. runCheck returns it when no update is needed.
var ErrUpToDate = errors.New("already up to date")

// CheckCLI checks the latest published release for the given product and
// returns it when a newer version is available, or ErrUpToDate when the
// local build is already up to date. It never downloads anything.
// proxyPort > 0 routes the fetches through the local easyss HTTP proxy at
// 127.0.0.1:<proxyPort>; otherwise a direct connection is used.
func CheckCLI(ctx context.Context, proxyPort int, product Product) (*Release, error) {
	return runCheck(ctx, NewClient(proxyPort), version.Tag())
}

// RunCLI performs a one-shot self-update for the given product from the
// command line: it checks the latest release and, when a newer one exists,
// downloads the release asset and replaces the running binary in place. It
// never restarts the process — the caller exits afterwards so the user or
// service manager starts the new binary. It returns ErrUpToDate when the
// local build is already the latest release. proxyPort > 0 routes the
// fetches through the local easyss HTTP proxy at 127.0.0.1:<proxyPort>;
// otherwise a direct connection is used.
func RunCLI(ctx context.Context, proxyPort int, product Product) error {
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

// RunCLICommand runs the "selfupdate" subcommand for the given product: it
// parses --check/--proxy-port, prints the subcommand help on --help/--h, and
// returns the process exit code (0 = success or help shown, 1 = failure,
// 2 = bad flags). It never restarts the process; the caller exits afterwards
// so the user or service manager starts the new binary.
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
		rel, err := CheckCLI(ctx, proxyPort, product)
		if err != nil {
			if errors.Is(err, ErrUpToDate) {
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

	if err := RunCLI(ctx, proxyPort, product); err != nil {
		if errors.Is(err, ErrUpToDate) {
			fmt.Println("已是最新版本:", version.Tag())
			return 0
		}
		log.Error("[SELFUPDATE] selfupdate", "err", err)
		return 1
	}
	fmt.Printf("已更新到最新版本，请重启 %s 完成升级\n", bin)
	return 0
}

// runCheck fetches the latest release and reports whether currentTag is
// behind it. It applies CheckTimeout to the whole check.
func runCheck(ctx context.Context, c *Client, currentTag string) (*Release, error) {
	checkCtx, cancel := context.WithTimeout(ctx, CheckTimeout)
	defer cancel()

	rel, err := CheckLatest(checkCtx, c)
	if err != nil {
		return nil, fmt.Errorf("check latest release: %w", err)
	}
	if !HasNewVersion(currentTag, rel.TagName) {
		return nil, ErrUpToDate
	}
	return rel, nil
}
