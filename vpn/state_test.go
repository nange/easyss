package vpn

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"tailscale.com/types/key"
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

// keyContent 是 RegenerateFile 测试用的"身份内容"：一把真 key 的落盘文本。
func keyContent(t *testing.T) []byte {
	t.Helper()
	b, err := key.NewNode().MarshalText()
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	return b
}

// TestRegenerateFile 固定"显式重新生成"这条路径与 LoadOrCreate 相反的那一半契约：
// 旧内容必须先被备份成 .bak，新内容才落到原路径上——备份是唯一的回滚凭据，而
// 地址里内嵌的 preshared key 只存在于那个文件里。
func TestRegenerateFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "client.key")

	// 1. 还没有文件时直接生成，不产生备份：那是一个新节点，没有东西可替换。
	backup, err := RegenerateFile(path, "client key", func() ([]byte, error) { return keyContent(t), nil })
	if err != nil {
		t.Fatalf("RegenerateFile on a missing file: %v", err)
	}
	if backup != "" {
		t.Errorf("backup = %q, want empty (there was nothing to replace)", backup)
	}
	requirePerm(t, "regenerated file", path, 0o600)

	// 2. 有文件时：备份内容 == 旧内容，且原路径上是新内容。
	old, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	backup, err = RegenerateFile(path, "client key", func() ([]byte, error) { return keyContent(t), nil })
	if err != nil {
		t.Fatalf("RegenerateFile on an existing file: %v", err)
	}
	if backup != path+BackupSuffix {
		t.Errorf("backup = %q, want %q", backup, path+BackupSuffix)
	}
	requirePerm(t, "backup", backup, 0o600)
	if got, err := os.ReadFile(backup); err != nil {
		t.Fatal(err)
	} else if string(got) != string(old) {
		t.Error("the backup does not hold the replaced content")
	}
	if got, err := os.ReadFile(path); err != nil {
		t.Fatal(err)
	} else if string(got) == string(old) {
		t.Error("the file still holds the old content after regeneration")
	}
}

// TestRegenerateFileKeepsExactlyOneBackup 固定"最多只留一份备份"这条策略：第二次重新
// 生成会用**本次的旧身份**覆盖那份备份，因此目录里始终只有一个 `.bak`。
//
// 这条断言是策略本身（而不是实现细节）：备份就是"上一次生效的身份"，它同时充当回滚点
// 与新旧对照物；保留更早的历史身份没有用途，却会让状态目录随时间稳定增长。
func TestRegenerateFileKeepsExactlyOneBackup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "node-identity.json")

	first, err := RegenerateFile(path, "node identity", func() ([]byte, error) { return []byte("first"), nil })
	if err != nil || first != "" {
		t.Fatalf("first RegenerateFile = (%q, %v), want (\"\", nil)", first, err)
	}
	second, err := RegenerateFile(path, "node identity", func() ([]byte, error) { return []byte("second"), nil })
	if err != nil {
		t.Fatal(err)
	}
	if second != path+BackupSuffix {
		t.Fatalf("second backup = %q, want %q", second, path+BackupSuffix)
	}
	if got, err := os.ReadFile(second); err != nil {
		t.Fatal(err)
	} else if string(got) != "first" {
		t.Errorf("the backup holds %q, want the replaced content \"first\"", got)
	}

	third, err := RegenerateFile(path, "node identity", func() ([]byte, error) { return []byte("third"), nil })
	if err != nil {
		t.Fatal(err)
	}
	if third != second {
		t.Errorf("backup path = %q, want the same single path %q", third, second)
	}
	if got, err := os.ReadFile(third); err != nil {
		t.Fatal(err)
	} else if string(got) != "second" {
		t.Errorf("the backup holds %q, want the most recently replaced content \"second\"", got)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var backups []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), filepath.Base(path)+BackupSuffix) {
			backups = append(backups, e.Name())
		}
	}
	if len(backups) != 1 {
		t.Errorf("state dir holds %v, want exactly one backup file", backups)
	}
}

// TestRegenerateFileReportsCreateError 固定"生成失败就什么都不写"：一个算不出新身份
// 的节点必须保持原样，而不是丢掉身份又拿不到新的。
func TestRegenerateFileReportsCreateError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "client.key")
	if err := os.WriteFile(path, []byte("keep-me"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := RegenerateFile(path, "client key", func() ([]byte, error) { return nil, errors.New("no entropy") })
	if err == nil {
		t.Fatal("RegenerateFile succeeded although create failed")
	}
	if got, err := os.ReadFile(path); err != nil {
		t.Fatal(err)
	} else if string(got) != "keep-me" {
		t.Errorf("the file holds %q, want it untouched", got)
	}
	if _, err := os.Stat(path + BackupSuffix); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a backup exists although nothing was replaced: %v", err)
	}
}

// TestIdentityRegenPending 固定"该不该提醒运维手上的地址还是旧的"这条判据。
//
// 它的三种"不提醒"同样重要：还没重新生成过（没有备份）、当前身份与备份一致（刚回滚完）、
// 以及身份文件缺失（那时命令本来就拿不到地址）。误报会让这行提示变成噪音，而它要提示的
// 恰恰是"对端连不上但两侧日志都没有明显错误"这种最难查的状态。
func TestIdentityRegenPending(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "node-identity.json")

	t.Run("没有身份文件时不提醒", func(t *testing.T) {
		if IdentityRegenPending(path) {
			t.Error("pending = true although there is no identity file")
		}
	})

	t.Run("没有备份时不提醒（还没重新生成过）", func(t *testing.T) {
		if err := os.WriteFile(path, []byte("current"), 0o600); err != nil {
			t.Fatal(err)
		}
		if IdentityRegenPending(path) {
			t.Error("pending = true although nothing was ever replaced")
		}
	})

	t.Run("当前身份与备份不同时提醒", func(t *testing.T) {
		if err := os.WriteFile(path+BackupSuffix, []byte("previous"), 0o600); err != nil {
			t.Fatal(err)
		}
		if !IdentityRegenPending(path) {
			t.Error("pending = false although the backup holds a different identity")
		}
	})

	t.Run("回滚（两份内容相同）之后不再提醒", func(t *testing.T) {
		if err := os.WriteFile(path+BackupSuffix, []byte("current"), 0o600); err != nil {
			t.Fatal(err)
		}
		if IdentityRegenPending(path) {
			t.Error("pending = true although the backup and the current identity are identical")
		}
	})
}

// TestPeerUpdateHint 固定"该去对端改哪个字段"这句话必须按**实际换掉**的那一半选。
//
// 提示说错字段的代价不是一行废话：运维照着改完仍然连不上，而他会以为是自己哪一步做错了。
func TestPeerUpdateHint(t *testing.T) {
	cases := []struct {
		replaced KeyKind
		want     string
		unwanted string
	}{
		{KindClientKey, RecipientNodeKey, RecipientAddress},
		{KindNodeIdentity, RecipientAddress, RecipientNodeKey},
		{KindNodeIdentity | KindClientKey, "新值", ""},
		{0, "新值", ""},
	}
	for _, tc := range cases {
		got := PeerUpdateHint(tc.replaced)
		if !strings.Contains(got, tc.want) {
			t.Errorf("PeerUpdateHint(%b) = %q, want it to mention %q", tc.replaced, got, tc.want)
		}
		if tc.unwanted != "" && strings.Contains(got, tc.unwanted) {
			t.Errorf("PeerUpdateHint(%b) = %q, should not mention %q", tc.replaced, got, tc.unwanted)
		}
	}
}
