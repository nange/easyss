package selfupdate

import (
	"context"
	"errors"
	"fmt"

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
