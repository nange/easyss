package selfupdate

import (
	"archive/zip"
	"context"
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
		{"", "v0.0.1", true},                   // dev build always updates
		{"v3.0.1-5-gabc1234", "v3.0.1", false}, // git describe suffix ignored
		{"v3.0.1-5-gabc1234", "v3.0.2", true},
		{"v3.1.0-rc1", "v3.1.0", true}, // prerelease < release
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
		{"v3.0.0-alpha.9", "v3.0.0-alpha.10", true}, // dot prefix + numeric tail goes numeric (lexical would say false)
		{"v3.0.0-alpha.10", "v3.0.0-alpha.9", false},
		{"v3.0.0-rc9", "v3.0.0-beta9", false}, // different prefix: lexical fallback, rc9 > beta9
		{"3.0.1", "v3.0.2", true},             // missing "v" prefix tolerated
		{"v3.0.1", "notasemver", true},        // unparsable falls back to inequality
	}

	for _, c := range cases {
		assert.Equal(t, c.want, HasNewVersion(c.current, c.latest),
			"current=%q latest=%q", c.current, c.latest)
	}
}

func TestPickAsset(t *testing.T) {
	rel := &Release{
		TagName: "v3.1.0",
		Assets: []Asset{
			{Name: "easyss-windows-amd64.zip"},
			{Name: "easyss-linux-arm64.zip"},
			{Name: "easyss-darwin-arm64.zip"},
			{Name: "easyss-server-linux-amd64.zip"},
		},
	}

	a := PickAsset(rel, "windows", "amd64")
	require.NotNil(t, a)
	assert.Equal(t, "easyss-windows-amd64.zip", a.Name)

	a = PickAsset(rel, "darwin", "arm64")
	require.NotNil(t, a)
	assert.Equal(t, "easyss-darwin-arm64.zip", a.Name)

	assert.Nil(t, PickAsset(rel, "linux", "386"))
	assert.Nil(t, PickAsset(rel, "freebsd", "amd64"))
}

func TestUnzipRejectsTraversal(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "dest")
	require.NoError(t, os.MkdirAll(dest, 0o755))

	zipPath := filepath.Join(dir, "rel-slip.zip")
	makeTestZip(t, zipPath, map[string]string{
		"easyss":           "binary",
		"Easyss.app/a/b":   "nested",
		"/abs/evil.txt":    "leading-slash", // leading slash is dropped by filepath.Join, stays inside
		"../evil.txt":      "evil",
		"a/../../evil.txt": "evil",
	})
	require.NoError(t, Unzip(zipPath, dest))

	// Legitimate entries are extracted inside dest.
	for _, rel := range []string{
		"easyss",
		filepath.Join("Easyss.app", "a", "b"),
		filepath.Join("abs", "evil.txt"),
	} {
		_, err := os.Stat(filepath.Join(dest, rel))
		require.NoError(t, err, "expected %s to exist", rel)
	}

	// Nothing may be written outside dest even with a zip-slip entry.
	_, err := os.Stat(filepath.Join(dir, "evil.txt"))
	assert.True(t, os.IsNotExist(err), "zip-slip entry must be rejected")
}

// makeTestZip builds a zip at zipPath with the given name/content pairs.
// Entries are written with unix mode 0755 so permission handling is exercised.
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
			CreatorVersion: 3<<8 | 20, // creator unix, spec 2.0
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

	require.NoError(t, Unzip(zipPath, dest))

	content, err := os.ReadFile(filepath.Join(dest, "easyss"))
	require.NoError(t, err)
	assert.Equal(t, "new-binary", string(content))

	content, err = os.ReadFile(filepath.Join(dest, "Easyss.app", "a.txt"))
	require.NoError(t, err)
	assert.Equal(t, "app-file", string(content))

	// The executable bit survives extraction (unix filesystems only).
	if runtime.GOOS != "windows" {
		info, err := os.Stat(filepath.Join(dest, "easyss"))
		require.NoError(t, err)
		assert.NotZero(t, info.Mode()&0o111, "binary should stay executable")
	}

	// Nothing may be written outside dest even with a zip-slip entry.
	slipPath := filepath.Join(dir, "rel-slip.zip")
	makeTestZip(t, slipPath, map[string]string{"../evil.txt": "evil"})
	require.NoError(t, Unzip(slipPath, dest))
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

	require.NoError(t, installAt(exe, staging))

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

	require.NoError(t, installAt(exe, staging))

	content, err := os.ReadFile(exe) // same path now resolves to the new bundle
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

	// Size mismatch is rejected.
	_, err := c.DownloadAsset(context.Background(), &Asset{
		Name:               "easyss-windows-amd64.zip",
		BrowserDownloadURL: srv.URL,
		Size:               5,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "size")

	// Size match succeeds and the temp file holds the downloaded bytes.
	path, err := c.DownloadAsset(context.Background(), &Asset{
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
		// Acting as an HTTP proxy, Host carries the target's authority; a
		// direct request carries the server's own host.
		if r.Host == "203.0.113.1:9" {
			_, _ = w.Write([]byte("via-proxy"))
			return
		}
		_, _ = w.Write([]byte(`{"app":"Easyss"}`))
	}))
	defer srv.Close()

	proxyURL, err := url.Parse(srv.URL)
	require.NoError(t, err)

	// Proxy path: the request must be served by the local proxy.
	c := &Client{
		proxy:  &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}},
		direct: &http.Client{},
	}
	resp, err := c.Get(context.Background(), "http://203.0.113.1:9/latest", nil)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	_ = resp.Body.Close()

	// Dead proxy: Get must fall back to the direct client.
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
