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

func filePerm(t *testing.T, path string) os.FileMode {
	t.Helper()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return st.Mode().Perm()
}

// requirePerm 断言权限位，Windows 跳过：那里的 Perm() 由只读属性合成（可写文件一律 0666），
// 断言没有意义，放宽取值只会变成同义反复。
func requirePerm(t *testing.T, what, path string, want os.FileMode) {
	t.Helper()
	if runtime.GOOS == "windows" {
		return
	}
	if got := filePerm(t, path); got != want {
		t.Errorf("%s permission = %o, want %o", what, got, want)
	}
}

// TestLoadKeyDoesNotCreate 固定只读加载的语义：文件缺失时是 fs.ErrNotExist 且不留文件，
// 损坏时与 LoadOrCreate 报同一句 corrupt（--dry-run 依赖前者）。
func TestLoadKeyDoesNotCreate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "client.key")

	if _, err := LoadKey(path); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("LoadKey(missing) = %v, want fs.ErrNotExist", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("LoadKey created the key file")
	}

	if err := os.WriteFile(path, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadKey(path)
	if err == nil || !strings.Contains(err.Error(), "corrupt") {
		t.Fatalf("LoadKey(corrupt) = %v, want a corrupt error", err)
	}
}

// TestLoadOrCreateKeyIsStable 固定 key 的跨重启稳定性与 0600 权限：allow_clients 白名单按它匹配。
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

// TestLoadOrCreateKeyRejectsCorruptFile 固定坏文件必须报 corrupt，不能静默换身份。
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

// TestStatePaths 固定三份状态文件同在一个目录（备份一个节点只需带走它）且路径互不冲突。
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

func keyContent(t *testing.T) []byte {
	t.Helper()
	b, err := key.NewNode().MarshalText()
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	return b
}

// TestRegenerateFile 固定"先备份旧内容、再落新内容"：备份是唯一回滚凭据，旧地址里内嵌的
// preshared key 只存在于那个文件。
func TestRegenerateFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "client.key")

	backup, err := RegenerateFile(path, "client key", func() ([]byte, error) { return keyContent(t), nil })
	if err != nil {
		t.Fatalf("RegenerateFile on a missing file: %v", err)
	}
	if backup != "" {
		t.Errorf("backup = %q, want empty (there was nothing to replace)", backup)
	}
	requirePerm(t, "regenerated file", path, 0o600)

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

// TestRegenerateFileKeepsExactlyOneBackup 固定"最多一份备份"：第二次重新生成会用本次的旧身份
// 覆盖它，因此目录里始终只有一个 .bak。
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

// TestRegenerateFileReportsCreateError 固定生成失败就什么都不写：节点保持原样，不丢身份。
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

// TestIdentityRegenPending 固定"该不该提醒"的判据：没有备份、刚回滚、身份文件缺失都不提醒。
// 误报会让提示变成噪音，而它针对的正是"对端连不上但两侧日志都正常"这种最难查的状态。
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

// TestPeerUpdateHint 固定提示只提真正换掉的那一半：说错字段会让运维照改完仍然连不上。
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
