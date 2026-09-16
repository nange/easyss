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

// maxUncompressedSize 限制 release zip 解压后的总大小上限。
const maxUncompressedSize = 512 << 20

// downloadAsset 将资产流式写入临时 zip 文件并返回其路径。
// 调用方负责删除该文件。
func (c *Client) downloadAsset(ctx context.Context, a *asset) (string, error) {
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

	_, copyErr := io.Copy(tmp, resp.Body) //nolint:gosec // 解压炸弹已由下面的资产大小检查限制
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
		// 上面的文件已经关闭，因此改用路径 stat：tmp.Stat() 在 Windows 上会因
		// 句柄已不存在而失败（报错 "The handle is invalid"）。
		info, statErr := os.Stat(tmp.Name())
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

// unzip 将 release zip 解压到 destDir。只解压普通文件和目录条目；
// 路径穿越（zip-slip）条目会被拒绝解压。复制过程中会自动校验 zip 的 CRC 校验和。
func unzip(zipPath, destDir string) error {
	r, err := zip.OpenReader(zipPath) //nolint:gosec // 路径来自我们自己的临时文件
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
			if err := os.MkdirAll(target, 0o755); err != nil { //nolint:gosec // 目录而非机密文件
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

// unzipFile 解压单个普通文件，用 maxSize 限制实际写入磁盘的字节数，
// 防止伪造的 zip 头超出解压预算。
func unzipFile(f *zip.File, target string, maxSize uint64) error {
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil { //nolint:gosec // 目录而非机密文件
		return fmt.Errorf("create dir %s: %w", filepath.Dir(target), err)
	}
	src, err := f.Open()
	if err != nil {
		return fmt.Errorf("open zip entry %s: %w", f.Name, err)
	}
	defer func() { _ = src.Close() }()

	dst, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode().Perm())
	if err != nil { //nolint:gosec // zip 条目路径已由调用方针对 destDir 校验
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

	// 即使 zip 在创建时丢失了 unix 权限位，也要保持可执行文件可执行。
	mode := f.Mode().Perm()
	if mode&0o111 != 0 && mode != 0o755 {
		if err := os.Chmod(target, 0o755); err != nil { //nolint:gosec // 可执行文件需要 0755 权限
			return fmt.Errorf("chmod %s: %w", target, err)
		}
	}
	return nil
}
