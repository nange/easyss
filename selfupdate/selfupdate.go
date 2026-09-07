// Package selfupdate implements checking GitHub releases, downloading and
// installing a new client build, and restarting the application process.
package selfupdate

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"time"
)

const (
	// CheckTimeout bounds a single GitHub release check.
	CheckTimeout = 15 * time.Second
	// DownloadTimeout bounds downloading and installing a release asset.
	DownloadTimeout = 10 * time.Minute
)

// Update downloads the release asset for the current platform, extracts it
// and installs it over the running executable (or the whole .app bundle on
// macOS). On success the new binary is in place and the caller should
// restart the process (see Restart). localHTTPPort is the local HTTP proxy
// port tried first for fetching; a direct connection is used as fallback.
func Update(ctx context.Context, localHTTPPort int, rel *Release) error {
	return UpdateFor(ctx, localHTTPPort, ProductClient, rel)
}

// UpdateFor is Update for a specific product (client, headless or server).
func UpdateFor(ctx context.Context, localHTTPPort int, product Product, rel *Release) error {
	return updateFor(ctx, NewClient(localHTTPPort), product, rel)
}

// updateFor downloads, extracts and installs the release asset for product
// using the given fetch client.
func updateFor(ctx context.Context, c *Client, product Product, rel *Release) error {
	asset := PickAssetFor(rel, product, runtime.GOOS, runtime.GOARCH)
	if asset == nil {
		return fmt.Errorf("no release asset for %s on %s/%s", product, runtime.GOOS, runtime.GOARCH)
	}

	ctx, cancel := context.WithTimeout(ctx, DownloadTimeout)
	defer cancel()

	zipPath, err := c.DownloadAsset(ctx, asset)
	if err != nil {
		return fmt.Errorf("download asset %s: %w", asset.Name, err)
	}
	defer func() { _ = os.Remove(zipPath) }()

	targetDir, err := installTargetDir()
	if err != nil {
		return err
	}
	// Stage next to the install target so the final rename stays on the
	// same volume (atomic).
	staging, err := os.MkdirTemp(targetDir, stagingPrefix)
	if err != nil {
		return permissionHint("create staging dir in "+targetDir, err)
	}
	defer func() { _ = os.RemoveAll(staging) }()

	if err := Unzip(zipPath, staging); err != nil {
		return fmt.Errorf("unzip asset %s: %w", asset.Name, err)
	}
	if err := InstallFor(staging, product); err != nil {
		return fmt.Errorf("install: %w", err)
	}
	return nil
}
