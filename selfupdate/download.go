package selfupdate

import (
	"archive/zip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// maxUncompressedSize bounds the total decompressed size of a release zip.
const maxUncompressedSize = 512 << 20

// DownloadAsset streams the asset into a temporary zip file and returns its
// path. The caller is responsible for removing the file.
func (c *Client) DownloadAsset(ctx context.Context, a *Asset) (string, error) {
	tmp, err := os.CreateTemp("", "easyss-update-*.zip")
	if err != nil {
		return "", fmt.Errorf("create temp file: %w", err)
	}

	remove := func() { _ = tmp.Close(); _ = os.Remove(tmp.Name()) }

	resp, err := c.Get(ctx, a.BrowserDownloadURL, nil)
	if err != nil {
		remove()
		return "", fmt.Errorf("download %s: %w", a.Name, err)
	}
	defer func() { _ = resp.Body.Close() }()

	_, copyErr := io.Copy(tmp, resp.Body) //nolint:gosec // decompression bomb is bounded by asset size check below
	closeErr := tmp.Close()
	switch {
	case copyErr != nil:
		remove()
		return "", fmt.Errorf("download %s: %w", a.Name, copyErr)
	case closeErr != nil:
		remove()
		return "", fmt.Errorf("save %s: %w", a.Name, closeErr)
	}

	if a.Size > 0 {
		info, statErr := tmp.Stat()
		if statErr != nil {
			remove()
			return "", fmt.Errorf("stat downloaded file: %w", statErr)
		}
		if info.Size() != a.Size {
			remove()
			return "", fmt.Errorf("downloaded %s size %d != expected %d", a.Name, info.Size(), a.Size)
		}
	}
	return tmp.Name(), nil
}

// Unzip extracts a release zip into destDir. Only regular file and directory
// entries are extracted; path traversal (zip-slip) entries are rejected. The
// zip CRC checksum is verified automatically while copying.
func Unzip(zipPath, destDir string) error {
	r, err := zip.OpenReader(zipPath) //nolint:gosec // path comes from our own temp file
	if err != nil {
		return fmt.Errorf("open zip %s: %w", zipPath, err)
	}
	defer func() { _ = r.Close() }()

	destClean := filepath.Clean(destDir) + string(os.PathSeparator)
	var total uint64
	for _, f := range r.File {
		target := filepath.Join(destDir, f.Name)
		if !strings.HasPrefix(target, destClean) {
			continue
		}
		info := f.FileInfo()
		switch {
		case info.IsDir():
			if err := os.MkdirAll(target, 0o755); err != nil { //nolint:gosec // directory, not secret
				return fmt.Errorf("create dir %s: %w", target, err)
			}
		case info.Mode().IsRegular():
			if total+f.UncompressedSize64 > maxUncompressedSize {
				return errors.New("release zip exceeds decompressed size limit")
			}
			if err := unzipFile(f, target, maxUncompressedSize-total); err != nil {
				return err
			}
			total += f.UncompressedSize64
		}
	}
	return nil
}

// unzipFile extracts a single regular file, bounding the bytes actually
// written to disk with maxSize so a lying zip header cannot exceed the
// decompression budget.
func unzipFile(f *zip.File, target string, maxSize uint64) error {
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil { //nolint:gosec // directory, not secret
		return fmt.Errorf("create dir %s: %w", filepath.Dir(target), err)
	}
	src, err := f.Open()
	if err != nil {
		return fmt.Errorf("open zip entry %s: %w", f.Name, err)
	}
	defer func() { _ = src.Close() }()

	dst, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode().Perm())
	if err != nil { //nolint:gosec // zip entry path is validated against destDir by the caller
		return fmt.Errorf("create %s: %w", target, err)
	}
	n, err := io.Copy(dst, io.LimitReader(src, int64(maxSize)))
	if err != nil {
		_ = dst.Close()
		_ = os.Remove(target)
		return fmt.Errorf("extract %s: %w", f.Name, err)
	}
	if uint64(n) >= maxSize {
		_ = dst.Close()
		_ = os.Remove(target)
		return fmt.Errorf("extract %s: entry exceeds decompressed size limit", f.Name)
	}
	if err := dst.Close(); err != nil {
		return fmt.Errorf("close %s: %w", target, err)
	}

	// Keep executables executable even if the zip lost the unix permission
	// bits when it was created.
	mode := f.Mode().Perm()
	if mode&0o111 != 0 && mode != 0o755 {
		if err := os.Chmod(target, 0o755); err != nil { //nolint:gosec // executable needs 0755
			return fmt.Errorf("chmod %s: %w", target, err)
		}
	}
	return nil
}
