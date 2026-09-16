// Package selfupdate 实现检查 GitHub release、下载并安装新的客户端构建，
// 以及重启应用程序进程。
package selfupdate

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"time"
)

const (
	// CheckTimeout 限制单次 GitHub release 检查的超时时间。
	CheckTimeout = 15 * time.Second
	// DownloadTimeout 限制下载并安装发布资产的超时时间。
	DownloadTimeout = 10 * time.Minute
)

// Update 下载当前平台的发布资产，解压并安装以覆盖正在运行的可执行文件
// （macOS 上为整个 .app bundle）。成功后新二进制已就位，调用方应重启进程
// （参见 Restart）。localHTTPPort 是获取时优先尝试的本地 HTTP 代理端口；
// 失败时回退到直连。
func Update(ctx context.Context, localHTTPPort int, rel *Release) error {
	return updateFor(ctx, NewClient(localHTTPPort), ProductClient, rel)
}

// updateFor 使用给定的获取客户端，下载、解压并安装 product 的发布资产。
func updateFor(ctx context.Context, c *Client, product Product, rel *Release) error {
	asset := pickAssetFor(rel, product, runtime.GOOS, runtime.GOARCH)
	if asset == nil {
		return fmt.Errorf("no release asset for %s on %s/%s", product, runtime.GOOS, runtime.GOARCH)
	}

	ctx, cancel := context.WithTimeout(ctx, DownloadTimeout)
	defer cancel()

	zipPath, err := c.downloadAsset(ctx, asset)
	if err != nil {
		return fmt.Errorf("download asset %s: %w", asset.Name, err)
	}
	defer func() { _ = os.Remove(zipPath) }()

	targetDir, err := installTargetDir()
	if err != nil {
		return err
	}
	// 在安装目标旁边创建暂存目录，使最终的 rename 保持在同一个卷内（原子操作）。
	staging, err := os.MkdirTemp(targetDir, stagingPrefix)
	if err != nil {
		return permissionHint("create staging dir in "+targetDir, err)
	}
	defer func() { _ = os.RemoveAll(staging) }()

	if err := unzip(zipPath, staging); err != nil {
		return fmt.Errorf("unzip asset %s: %w", asset.Name, err)
	}
	if err := installFor(staging, product); err != nil {
		return fmt.Errorf("install: %w", err)
	}
	return nil
}
