package vpn

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// filePerm 返回文件权限位。
func filePerm(t *testing.T, path string) os.FileMode {
	t.Helper()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return st.Mode().Perm()
}

// requirePerm 断言 path 的权限位。
//
// Windows 没有 POSIX 权限位：Go 报告的 Perm() 是从"只读"属性合成的（可写文件
// 一律 0666），因此那里既不可能满足 0600、断言也不代表任何真实约束。跳过而不是
// 放宽取值，否则这条用例在 Windows 上会退化成一句同义反复。
func requirePerm(t *testing.T, what, path string, want os.FileMode) {
	t.Helper()
	if runtime.GOOS == "windows" {
		return
	}
	if got := filePerm(t, path); got != want {
		t.Errorf("%s permission = %o, want %o", what, got, want)
	}
}

// TestLoadOrCreateKeyIsStable 固定 client key 与 DERP key 的稳定性与权限。
// client key 跨重启稳定是 vpn.allow_clients 白名单可用的前提。
func TestLoadOrCreateKeyIsStable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client.key")

	first, err := LoadOrCreateKey(path)
	if err != nil {
		t.Fatalf("first LoadOrCreateKey: %v", err)
	}
	if first.IsZero() {
		t.Fatal("generated key is zero")
	}
	requirePerm(t, "key file", path, 0o600)
	if !strings.HasPrefix(NodeKeyString(first), "nodekey:") {
		t.Errorf("NodeKeyString = %q, want a nodekey: prefix (that is the vpn.allow_clients format)", NodeKeyString(first))
	}

	second, err := LoadOrCreateKey(path)
	if err != nil {
		t.Fatalf("second LoadOrCreateKey: %v", err)
	}
	if !first.Equal(second) {
		t.Error("client key changed across loads: vpn.allow_clients would break on every restart")
	}
}

// TestLoadOrCreateKeyRejectsCorruptFile 与身份文件同一条契约。
func TestLoadOrCreateKeyRejectsCorruptFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "derp.key")
	if err := os.WriteFile(path, []byte("not-a-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadOrCreateKey(path)
	if err == nil {
		t.Fatal("LoadOrCreateKey accepted a corrupt file, want error")
	}
	if !strings.Contains(err.Error(), "corrupt") {
		t.Errorf("error %q should say the file is corrupt", err)
	}
}

// TestStatePaths 固定三份状态文件的路径形态：它们都在同一个目录下（备份一个
// 节点只需带走一个目录），且文件名互不冲突。
func TestStatePaths(t *testing.T) {
	paths := map[string]string{
		"node identity": NodeIdentityPath(),
		"client key":    ClientKeyPath(),
		"derp key":      DERPKeyPath(),
	}
	seen := make(map[string]string, len(paths))
	for what, p := range paths {
		if p == "" {
			t.Fatalf("%s path is empty", what)
		}
		if prev, dup := seen[p]; dup {
			t.Errorf("%s and %s share the path %s", prev, what, p)
		}
		seen[p] = what
	}
	dir := StateDir()
	for what, p := range paths {
		if got := filepath.Dir(p); got != dir {
			t.Errorf("%s path %s is not under the state dir %s", what, p, dir)
		}
	}
}
