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

// Update 下载、解压并安装当前平台的发布资产，覆盖正在运行的可执行文件（macOS 上为整个
// .app bundle）；成功后调用方必须重启进程。下载优先走 localHTTPPort，失败回退直连。
func Update(ctx context.Context, localHTTPPort int, rel *Release) error {
	c := NewClient(localHTTPPort)
	// 下载用的连接池随本次更新结束一起回收，不留给长驻进程（见 Client.Close）。
	defer c.Close()
	return updateFor(ctx, c, ProductClient, rel)
}

// updateFor 使用给定的获取客户端，下载、解压并安装 product 的发布资产。
func updateFor(ctx context.Context, c *Client, product Product, rel *Release) error {
	asset := pickAssetFor(rel, product, runtime.GOOS, runtime.GOARCH)
	if asset == nil {
		return fmt.Errorf("release %s has no %s asset for %s/%s", rel.TagName, product, runtime.GOOS, runtime.GOARCH)
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
