package selfupdate

import (
	"archive/zip"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHasNewVersion(t *testing.T) {
	cases := []struct {
		current string
		latest  string
		want    bool
	}{
		{"v3.0.1", "v3.1.0", true},
		{"v3.1.0", "v3.0.1", false},
		{"v3.1.0", "v3.1.0", false},
		{"v3.0", "v3.0.1", true},
		{"", "v0.0.1", true},                   // 开发构建总是更新
		{"v3.0.1-5-gabc1234", "v3.0.1", false}, // git describe 后缀被忽略
		{"v3.0.1-5-gabc1234", "v3.0.2", true},
		{"v3.1.0-rc1", "v3.1.0", true}, // 预发布 < 正式版
		{"v3.0.0-rc9", "v3.0.0-rc11", true},
		{"v3.0.0-rc11", "v3.0.0-rc9", false},
		{"v3.0.0-rc10", "v3.0.0-rc9", false},
		{"v3.0.0-rc9", "v3.0.0", true},
		{"v3.0.0", "v3.0.0-rc9", false},
		{"v3.0.0-rc9", "v3.0.0-rc9.1", true},
		{"v3.0.0-rc9.1", "v3.0.0-rc9", false},
		{"v3.0.0-rc9.1", "v3.0.0-rc10", true},
		{"v3.0.0-beta9", "v3.0.0-beta11", true},
		{"v3.0.0-beta11", "v3.0.0-beta9", false},
		{"v3.0.0-alpha.9", "v3.0.0-alpha.10", true}, // 点号前缀 + 数字尾部按数值比较（字典序会得到 false）
		{"v3.0.0-alpha.10", "v3.0.0-alpha.9", false},
		{"v3.0.0-rc9", "v3.0.0-beta9", false}, // 前缀不同：回退到字典序，rc9 > beta9
		{"3.0.1", "v3.0.2", true},             // 缺少 "v" 前缀也能解析
		{"v3.0.1", "notasemver", true},        // 无法解析时回退到不等比较
	}

	for _, c := range cases {
		assert.Equal(t, c.want, HasNewVersion(c.current, c.latest),
			"current=%q latest=%q", c.current, c.latest)
	}
}

func TestPickAsset(t *testing.T) {
	rel := &Release{
		TagName: "v3.1.0",
		Assets: []asset{
			{Name: "easyss-windows-amd64.zip"},
			{Name: "easyss-linux-arm64.zip"},
			{Name: "easyss-darwin-arm64.zip"},
			{Name: "easyss-server-linux-amd64.zip"},
		},
	}

	a := pickAsset(rel, "windows", "amd64")
	require.NotNil(t, a)
	assert.Equal(t, "easyss-windows-amd64.zip", a.Name)

	a = pickAsset(rel, "darwin", "arm64")
	require.NotNil(t, a)
	assert.Equal(t, "easyss-darwin-arm64.zip", a.Name)

	assert.Nil(t, pickAsset(rel, "linux", "386"))
	assert.Nil(t, pickAsset(rel, "freebsd", "amd64"))
}

func TestPickAssetFor(t *testing.T) {
	rel := &Release{
		TagName: "v3.1.0",
		Assets: []asset{
			{Name: "easyss-windows-amd64.zip"},
			{Name: "easyss-headless-linux-amd64.zip"},
			{Name: "easyss-server-linux-amd64.zip"},
			{Name: "easyss-server-windows-amd64.zip"},
		},
	}

	cases := []struct {
		product Product
		goos    string
		goarch  string
		want    string
	}{
		{ProductServer, "linux", "amd64", "easyss-server-linux-amd64.zip"},
		{ProductServer, "windows", "amd64", "easyss-server-windows-amd64.zip"},
		{ProductHeadless, "linux", "amd64", "easyss-headless-linux-amd64.zip"},
		{ProductClient, "windows", "amd64", "easyss-windows-amd64.zip"},
	}
	for _, c := range cases {
		a := pickAssetFor(rel, c.product, c.goos, c.goarch)
		require.NotNil(t, a, "%s/%s/%s", c.product, c.goos, c.goarch)
		assert.Equal(t, c.want, a.Name)
	}

	// 该产品在该平台没有已发布的资产。
	assert.Nil(t, pickAssetFor(rel, ProductServer, "darwin", "arm64"))
	assert.Nil(t, pickAssetFor(rel, ProductHeadless, "windows", "amd64"))
}

func TestRunCheck(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"tag_name":"v1.0.0","assets":[]}`))
	}))
	defer srv.Close()

	orig := repoLatestURL
	repoLatestURL = srv.URL + "/latest"
	defer func() { repoLatestURL = orig }()

	c := &Client{direct: srv.Client()}

	// 已是最新版本。
	_, err := runCheck(context.Background(), c, "v9.9.9")
	assert.ErrorIs(t, err, errUpToDate)

	// 有更新版本可用（runCheck 从不下载）。
	rel, err := runCheck(context.Background(), c, "v0.0.1")
	require.NoError(t, err)
	require.NotNil(t, rel)
	assert.Equal(t, "v1.0.0", rel.TagName)
}

func TestRunCheckFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	orig := repoLatestURL
	repoLatestURL = srv.URL + "/latest"
	defer func() { repoLatestURL = orig }()

	c := &Client{direct: srv.Client()}
	_, err := runCheck(context.Background(), c, "v0.0.1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "check latest release")
}

func TestRunCLICommandHelp(t *testing.T) {
	// --help/-h 打印子命令用法并以 0 退出，不发起任何网络请求。
	assert.Equal(t, 0, RunCLICommand([]string{"--help"}, ProductHeadless))
	assert.Equal(t, 0, RunCLICommand([]string{"-h"}, ProductHeadless))
}

func TestRunCLICommandBadFlag(t *testing.T) {
	// 未知标志以 2 退出，与标准 flag 包的错误约定一致。
	assert.Equal(t, 2, RunCLICommand([]string{"--bogus"}, ProductHeadless))
}

func TestRunCLICommandRejectsPositionalArg(t *testing.T) {
	// 位置参数不得被静默忽略：否则 "selfupdate v3.0.0" 会变成一次意料之外的
	// 网络请求（升级到最新 release）。指定版本必须走 --version。
	assert.Equal(t, 2, RunCLICommand([]string{"v3.0.0"}, ProductHeadless))
	assert.Equal(t, 2, RunCLICommand([]string{"--check", "v3.0.0"}, ProductHeadless))
}

func TestCheckTag(t *testing.T) {
	releaseBody := makeReleaseBody(t, "v1.2.3", "easyss-linux-amd64.zip")
	preBody := makeReleaseBody(t, "v3.0.0-rc1")

	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		switch r.URL.Path {
		case "/releases/tags/v1.2.3":
			_, _ = w.Write([]byte(releaseBody))
		case "/releases/tags/v3.0.0-rc1":
			_, _ = w.Write([]byte(preBody))
		case "/releases/tags/boom":
			http.Error(w, "boom", http.StatusInternalServerError)
		default:
			http.Error(w, `{"message":"Not Found"}`, http.StatusNotFound)
		}
	}))
	defer srv.Close()

	orig := repoReleaseTagURL
	repoReleaseTagURL = srv.URL + "/releases/tags/%s"
	defer func() { repoReleaseTagURL = orig }()

	c := &Client{direct: srv.Client()}

	rel, err := checkTag(context.Background(), c, "v1.2.3")
	require.NoError(t, err)
	assert.Equal(t, "v1.2.3", rel.TagName)
	assert.Equal(t, "/releases/tags/v1.2.3", gotPath)
	require.Len(t, rel.Assets, 1)
	assert.Equal(t, "easyss-linux-amd64.zip", rel.Assets[0].Name)

	// 该端点也会返回预发布版本，这正是调试时需要的（/releases/latest 不会）。
	rel, err = checkTag(context.Background(), c, "v3.0.0-rc1")
	require.NoError(t, err)
	assert.Equal(t, "v3.0.0-rc1", rel.TagName)

	// tag 不存在：必须可被调用方识别，以便给出「tag 需完全一致」的提示。
	_, err = checkTag(context.Background(), c, "v9.9.9")
	require.Error(t, err)
	assert.ErrorIs(t, err, errReleaseNotFound)
	assert.Contains(t, err.Error(), "v9.9.9")

	// 其它状态的错误不得被误判为「版本不存在」。
	_, err = checkTag(context.Background(), c, "boom")
	require.Error(t, err)
	assert.NotErrorIs(t, err, errReleaseNotFound)
}

func TestResolveReleaseExplicitVersion(t *testing.T) {
	latestBody := makeReleaseBody(t, "v1.0.0", "easyss-linux-amd64.zip")
	tagBody := makeReleaseBody(t, "v1.0.0", "easyss-linux-amd64.zip")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/latest" {
			_, _ = w.Write([]byte(latestBody))
			return
		}
		_, _ = w.Write([]byte(tagBody))
	}))
	defer srv.Close()

	origLatest, origTag := repoLatestURL, repoReleaseTagURL
	repoLatestURL = srv.URL + "/latest"
	repoReleaseTagURL = srv.URL + "/releases/tags/%s"
	defer func() { repoLatestURL, repoReleaseTagURL = origLatest, origTag }()

	c := &Client{direct: srv.Client()}

	// 显式指定的版本比本地更旧：必须照样返回它，而不是 errUpToDate，
	// 因为重装当前版本与回退到旧版本正是该参数的用途。
	rel, err := resolveRelease(context.Background(), c, "v9.9.9", "v1.0.0")
	require.NoError(t, err)
	assert.Equal(t, "v1.0.0", rel.TagName)

	// 未指定版本时保持原语义：本地已不落后于最新 release 即 errUpToDate。
	_, err = resolveRelease(context.Background(), c, "v9.9.9", "")
	assert.ErrorIs(t, err, errUpToDate)
}

func TestRunCLICommandVersionNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"message":"Not Found"}`, http.StatusNotFound)
	}))
	defer srv.Close()

	orig := repoReleaseTagURL
	repoReleaseTagURL = srv.URL + "/releases/tags/%s"
	defer func() { repoReleaseTagURL = orig }()

	// 不存在的 tag：检查与安装路径都以 1 退出，且不会下载任何内容。
	assert.Equal(t, 1, RunCLICommand([]string{"--check", "--version", "v9.9.9"}, ProductHeadless))
	assert.Equal(t, 1, RunCLICommand([]string{"--version", "v9.9.9"}, ProductHeadless))
}

func TestRunCLICommandCheckVersionAssets(t *testing.T) {
	cases := []struct {
		name string
		body string
		want int
	}{
		{
			name: "有当前平台的资产",
			body: makeReleaseBody(t, "v1.0.0", ProductHeadless.assetName(runtime.GOOS, runtime.GOARCH)),
			want: 0,
		},
		{
			name: "没有当前平台的资产",
			body: makeReleaseBody(t, "v1.0.0", "easyss-headless-plan9-mips.zip"),
			want: 1,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			body := c.body
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(body))
			}))
			defer srv.Close()

			orig := repoReleaseTagURL
			repoReleaseTagURL = srv.URL + "/releases/tags/%s"
			defer func() { repoReleaseTagURL = orig }()

			// --check 只查询，不下载也不替换运行中的测试二进制。
			assert.Equal(t, c.want, RunCLICommand([]string{"--check", "--version", "v1.0.0"}, ProductHeadless))
		})
	}
}

func TestRunCLICommandVersionNoAsset(t *testing.T) {
	body := makeReleaseBody(t, "v1.0.0", "easyss-headless-plan9-mips.zip")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	orig := repoReleaseTagURL
	repoReleaseTagURL = srv.URL + "/releases/tags/%s"
	defer func() { repoReleaseTagURL = orig }()

	// 安装路径在「挑选资产」阶段就失败，早于下载与 installFor，
	// 因此该测试不会覆盖正在运行的测试二进制。
	assert.Equal(t, 1, RunCLICommand([]string{"--version", "v1.0.0"}, ProductHeadless))
}

// makeReleaseBody 生成一个最小的 release API 响应体，资产只带名称与下载地址。
func makeReleaseBody(t *testing.T, tag string, assetNames ...string) string {
	t.Helper()

	rel := Release{TagName: tag, Name: tag}
	for _, name := range assetNames {
		rel.Assets = append(rel.Assets, asset{
			Name:               name,
			BrowserDownloadURL: "http://127.0.0.1:9/" + name,
			Size:               1,
		})
	}
	b, err := json.Marshal(rel)
	require.NoError(t, err)
	return string(b)
}

func TestUnzipRejectsTraversal(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "dest")
	require.NoError(t, os.MkdirAll(dest, 0o755))

	zipPath := filepath.Join(dir, "rel-slip.zip")
	makeTestZip(t, zipPath, map[string]string{
		"easyss":           "binary",
		"Easyss.app/a/b":   "nested",
		"/abs/evil.txt":    "leading-slash", // 前导斜杠会被 filepath.Join 去掉，因此仍落在解压目录内
		"../evil.txt":      "evil",
		"a/../../evil.txt": "evil",
	})
	require.NoError(t, unzip(zipPath, dest))

	// 合法条目都被解压到 dest 内。
	for _, rel := range []string{
		"easyss",
		filepath.Join("Easyss.app", "a", "b"),
		filepath.Join("abs", "evil.txt"),
	} {
		_, err := os.Stat(filepath.Join(dest, rel))
		require.NoError(t, err, "expected %s to exist", rel)
	}

	// 即使存在 zip-slip 条目，也不得在 dest 之外写入任何内容。
	_, err := os.Stat(filepath.Join(dir, "evil.txt"))
	assert.True(t, os.IsNotExist(err), "zip-slip entry must be rejected")
}

// makeTestZip 用给定的 name/content 键值对在 zipPath 处构建一个 zip。
// 条目以 unix 模式 0755 写入，以覆盖权限处理逻辑。
func makeTestZip(t *testing.T, zipPath string, files map[string]string) {
	t.Helper()

	f, err := os.Create(zipPath)
	require.NoError(t, err)
	defer func() { _ = f.Close() }()

	w := zip.NewWriter(f)
	for name, content := range files {
		fw, err := w.CreateHeader(&zip.FileHeader{
			Name:           name,
			Method:         zip.Deflate,
			CreatorVersion: 3<<8 | 20, // 创建者 unix，规范 2.0
			ExternalAttrs:  0o755 << 16,
		})
		require.NoError(t, err)
		_, err = fw.Write([]byte(content))
		require.NoError(t, err)
	}
	require.NoError(t, w.Close())
}

func TestUnzip(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "dest")
	require.NoError(t, os.MkdirAll(dest, 0o755))

	zipPath := filepath.Join(dir, "rel.zip")
	makeTestZip(t, zipPath, map[string]string{
		"easyss":           "new-binary",
		"Easyss.app/a.txt": "app-file",
	})

	require.NoError(t, unzip(zipPath, dest))

	content, err := os.ReadFile(filepath.Join(dest, "easyss"))
	require.NoError(t, err)
	assert.Equal(t, "new-binary", string(content))

	content, err = os.ReadFile(filepath.Join(dest, "Easyss.app", "a.txt"))
	require.NoError(t, err)
	assert.Equal(t, "app-file", string(content))

	// 可执行位在解压后仍然保留（仅 unix 文件系统）。
	if runtime.GOOS != "windows" {
		info, err := os.Stat(filepath.Join(dest, "easyss"))
		require.NoError(t, err)
		assert.NotZero(t, info.Mode()&0o111, "binary should stay executable")
	}

	// 即使存在 zip-slip 条目，也不得在 dest 之外写入任何内容。
	slipPath := filepath.Join(dir, "rel-slip.zip")
	makeTestZip(t, slipPath, map[string]string{"../evil.txt": "evil"})
	require.NoError(t, unzip(slipPath, dest))
	_, err = os.Stat(filepath.Join(dir, "evil.txt"))
	assert.True(t, os.IsNotExist(err), "zip-slip entry must be rejected")
}

func TestInstallAtBinary(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("running-exe swap via .old rename is the windows flow")
	}

	dir := t.TempDir()
	exe := filepath.Join(dir, "easyss.exe")
	require.NoError(t, os.WriteFile(exe, []byte("old"), 0o755))

	staging := filepath.Join(dir, stagingPrefix+"1")
	require.NoError(t, os.MkdirAll(staging, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(staging, "easyss.exe"), []byte("new"), 0o755))

	require.NoError(t, installAt(exe, staging, ProductClient))

	content, err := os.ReadFile(exe)
	require.NoError(t, err)
	assert.Equal(t, "new", string(content))

	old, err := os.ReadFile(exe + ".old")
	require.NoError(t, err)
	assert.Equal(t, "old", string(old))
}

func TestInstallAtBundle(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "Easyss.app", "Contents", "MacOS", "easyss")
	require.NoError(t, os.MkdirAll(filepath.Dir(exe), 0o755))
	require.NoError(t, os.WriteFile(exe, []byte("old"), 0o755))

	staging := filepath.Join(dir, stagingPrefix+"1")
	stagedExe := filepath.Join(staging, "Easyss.app", "Contents", "MacOS", "easyss")
	require.NoError(t, os.MkdirAll(filepath.Dir(stagedExe), 0o755))
	require.NoError(t, os.WriteFile(stagedExe, []byte("new"), 0o755))

	require.NoError(t, installAt(exe, staging, ProductClient))

	content, err := os.ReadFile(exe) // 同一路径现在指向新的 bundle
	require.NoError(t, err)
	assert.Equal(t, "new", string(content))

	old, err := os.ReadFile(filepath.Join(dir, "Easyss.app.old", "Contents", "MacOS", "easyss"))
	require.NoError(t, err)
	assert.Equal(t, "old", string(old))

	assert.Equal(t, filepath.Join(dir, "Easyss.app"), appBundleRoot(exe))
}

func TestRestartArgs(t *testing.T) {
	orig := os.Args
	defer func() { os.Args = orig }()

	os.Args = []string{"easyss", "-c", "config.json", "--daemon"}
	assert.Equal(t, []string{"-c", "config.json", "--daemon=false"}, restartArgs())

	os.Args = []string{"easyss", "-daemon=true", "-log-file", "a.log"}
	assert.Equal(t, []string{"-log-file", "a.log", "--daemon=false"}, restartArgs())

	os.Args = []string{"easyss", "-daemon", "false", "-c", "config.json"}
	assert.Equal(t, []string{"-c", "config.json", "--daemon=false"}, restartArgs())

	os.Args = []string{"easyss"}
	assert.Equal(t, []string{"--daemon=false"}, restartArgs())
}

func TestUnzipFileSizeLimit(t *testing.T) {
	dir := t.TempDir()
	zipPath := filepath.Join(dir, "big.zip")
	makeTestZip(t, zipPath, map[string]string{"big.bin": "xx"}) // 2 bytes

	r, err := zip.OpenReader(zipPath)
	require.NoError(t, err)
	defer func() { _ = r.Close() }()
	require.Len(t, r.File, 1)

	target := filepath.Join(dir, "out", "big.bin")
	err = unzipFile(r.File[0], target, 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds decompressed size limit")

	_, statErr := os.Stat(target)
	assert.True(t, os.IsNotExist(statErr), "oversized file must be cleaned up")
}

func TestPermissionHint(t *testing.T) {
	err := permissionHint("install", &fs.PathError{Op: "open", Path: "/x", Err: fs.ErrPermission})
	assert.Contains(t, err.Error(), "无写权限")

	err = permissionHint("install", errors.New("boom"))
	assert.Equal(t, "install: boom", err.Error())
}

func TestDownloadAssetSizeCheck(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("xx")) // 2 bytes
	}))
	defer srv.Close()

	c := &Client{direct: srv.Client()}

	// 大小不匹配会被拒绝。
	_, err := c.downloadAsset(context.Background(), &asset{
		Name:               "easyss-windows-amd64.zip",
		BrowserDownloadURL: srv.URL,
		Size:               5,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "size")

	// 大小匹配时下载成功，临时文件保存了下载的字节。
	path, err := c.downloadAsset(context.Background(), &asset{
		Name:               "easyss-windows-amd64.zip",
		BrowserDownloadURL: srv.URL,
		Size:               2,
	})
	require.NoError(t, err)
	defer func() { _ = os.Remove(path) }()

	content, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "xx", string(content))
}

func TestClientProxyFallback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 作为 HTTP 代理时，Host 携带目标地址的 authority；直连请求则携带
		// 服务器自身的主机名。
		if r.Host == "203.0.113.1:9" {
			_, _ = w.Write([]byte("via-proxy"))
			return
		}
		_, _ = w.Write([]byte(`{"app":"Easyss"}`))
	}))
	defer srv.Close()

	proxyURL, err := url.Parse(srv.URL)
	require.NoError(t, err)

	// 代理路径：请求必须由本地代理服务。
	c := &Client{
		proxy:  &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}},
		direct: &http.Client{},
	}
	resp, err := c.Get(context.Background(), "http://203.0.113.1:9/latest", nil)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	_ = resp.Body.Close()

	// 代理不可用：Get 必须回退到直连客户端。
	dead := &Client{
		proxy:  &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(deadProxyURL)}},
		direct: srv.Client(),
	}
	resp, err = dead.Get(context.Background(), srv.URL, nil)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	body := make([]byte, 64)
	n, _ := resp.Body.Read(body)
	assert.Contains(t, string(body[:n]), "Easyss")
}

var deadProxyURL = &url.URL{Scheme: "http", Host: "127.0.0.1:1"}
