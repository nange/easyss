package vpnnode

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	tailcat "github.com/tailscale/tailcat"

	"github.com/nange/easyss/v3/vpn"
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
// 一律 0666、目录 0666），因此那里既不可能满足 0600/0700、断言也不代表任何真实
// 约束。跳过而不是放宽取值，否则这条用例在 Windows 上会退化成一句同义反复。
func requirePerm(t *testing.T, what, path string, want os.FileMode) {
	t.Helper()
	if runtime.GOOS == "windows" {
		return
	}
	if got := filePerm(t, path); got != want {
		t.Errorf("%s permission = %o, want %o", what, got, want)
	}
}

// dropKey 从一个 JSON 对象里删掉指定字段，返回新的 JSON（测试用）。
func dropKey(t *testing.T, raw json.RawMessage, key string) json.RawMessage {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal %s: %v", raw, err)
	}
	delete(m, key)
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestLoadOrCreateNodeIdentityIsStable 固定"密钥持久化后地址稳定"：这是整个零控制
// 面设计的前提——对端配置里粘的是本节点的地址，换一次身份就要所有对端重配。
//
// 同时固定落盘权限（目录 0700、文件 0600），因为身份文件里含 preshared key，
// 等价于对端面的接入凭据。
func TestLoadOrCreateNodeIdentityIsStable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state", "node-identity.json")

	first, err := LoadOrCreateNodeIdentity(path)
	if err != nil {
		t.Fatalf("first LoadOrCreateNodeIdentity: %v", err)
	}
	requirePerm(t, "key file", path, 0o600)
	requirePerm(t, "state dir", filepath.Dir(path), 0o700)

	second, err := LoadOrCreateNodeIdentity(path)
	if err != nil {
		t.Fatalf("second LoadOrCreateNodeIdentity: %v", err)
	}
	if !first.Private.Equal(second.Private) {
		t.Error("node private key changed across loads")
	}
	if !first.Public.PresharedKey.Equal(second.Public.PresharedKey) {
		t.Error("preshared key changed across loads")
	}
	if first.Public.ServerDiscoPublic.String() != second.Public.ServerDiscoPublic.String() {
		t.Error("disco public key changed across loads")
	}

	// 地址必须逐字节一致，且仍是完整展开格式（内嵌 region）。
	region, err := vpn.BuildRegion("relay.example.com:8443")
	if err != nil {
		t.Fatal(err)
	}
	addr := first.Address(region)
	if addr != second.Address(region) {
		t.Error("tailcat address changed across loads")
	}
	if err := AssertFullAddr(addr); err != nil {
		t.Errorf("persisted identity produced a non self-contained address: %v", err)
	}
}

// TestLoadOrCreateNodeIdentityRejectsCorruptFile 固定"损坏时报错且绝不静默覆盖"：
// 覆盖等于换掉身份，而所有对端都要跟着改配置，必须由人决定。
func TestLoadOrCreateNodeIdentityRejectsCorruptFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "node-identity.json")
	const garbage = "{ this is not json"
	if err := os.WriteFile(path, []byte(garbage), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := LoadOrCreateNodeIdentity(path)
	if err == nil {
		t.Fatal("LoadOrCreateNodeIdentity accepted a corrupt file, want error")
	}
	if !strings.Contains(err.Error(), "corrupt") {
		t.Errorf("error %q should say the file is corrupt", err)
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("error %q should name the file", err)
	}

	got, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(got) != garbage {
		t.Error("corrupt identity file was overwritten")
	}
}

// TestLoadOrCreateNodeIdentityRejectsIncompleteFile 固定缺字段的报错发生在读取
// 阶段：这些字段缺失时 tailcat 会在启动或首次访问对端时才失败，而那时的错误
// 不会指向密钥文件。
func TestLoadOrCreateNodeIdentityRejectsIncompleteFile(t *testing.T) {
	// 基线是一份**完整**的身份：逐项删字段才说明得了"缺失被检出"。
	full, err := json.Marshal(NodeIdentity{PrivateKey: *tailcat.NewPrivateKey()})
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name   string
		mutate func(m map[string]json.RawMessage)
		want   string
	}{
		{
			name:   "缺少 node 私钥",
			mutate: func(m map[string]json.RawMessage) { delete(m, "Private") },
			want:   "node private key is missing",
		},
		{
			name:   "缺少整个 Public",
			mutate: func(m map[string]json.RawMessage) { m["Public"] = json.RawMessage(`{}`) },
			want:   "server public key is missing",
		},
		{
			name: "缺少 disco 公钥",
			mutate: func(m map[string]json.RawMessage) {
				m["Public"] = dropKey(t, m["Public"], "ServerDiscoPublic")
			},
			want: "disco public key is missing",
		},
		{
			name: "缺少 preshared key",
			mutate: func(m map[string]json.RawMessage) {
				m["Public"] = dropKey(t, m["Public"], "PresharedKey")
			},
			want: "preshared key is missing",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var m map[string]json.RawMessage
			if err := json.Unmarshal(full, &m); err != nil {
				t.Fatal(err)
			}
			tc.mutate(m)
			data, err := json.Marshal(m)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "node-identity.json")
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			_, err = LoadOrCreateNodeIdentity(path)
			if err == nil {
				t.Fatalf("LoadOrCreateNodeIdentity(%s) = nil, want error", data)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q should contain %q", err, tc.want)
			}
		})
	}
}

// TestRegenerateNodeIdentity 固定"重新生成身份"的三条契约：
//
//   - 新身份与旧身份不同（否则命令没有意义）；
//   - 旧身份被完整备份到 <path>.bak（地址里内嵌的 preshared key 只存在于这个文件，
//     备份是回滚的唯一凭据）；
//   - 生成出来的文件能被真实读回（缺字段的身份比没有文件更难排查）。
func TestRegenerateNodeIdentity(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "node-identity.json")

	before, err := LoadOrCreateNodeIdentity(path)
	if err != nil {
		t.Fatalf("LoadOrCreateNodeIdentity: %v", err)
	}
	oldBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	backup, err := RegenerateNodeIdentityFile(path, NewNodeIdentity())
	if err != nil {
		t.Fatalf("RegenerateNodeIdentity: %v", err)
	}
	if backup != path+vpn.BackupSuffix {
		t.Errorf("backup = %q, want %q", backup, path+vpn.BackupSuffix)
	}
	if got, err := os.ReadFile(backup); err != nil {
		t.Fatal(err)
	} else if string(got) != string(oldBytes) {
		t.Error("the backup does not hold the replaced identity")
	}

	after, err := LoadOrCreateNodeIdentity(path)
	if err != nil {
		t.Fatalf("LoadOrCreateNodeIdentity after regeneration: %v", err)
	}
	if after.Private.Equal(before.Private) {
		t.Error("the node private key did not change")
	}
	if after.Public.PresharedKey.Equal(before.Public.PresharedKey) {
		t.Error("the preshared key did not change: the old address would keep working")
	}
	// 两个公钥都由私钥/内部派生，换私钥就必须一起换；只换一半会让节点身份自相矛盾。
	if after.Public.ServerPublic.Equal(before.Public.ServerPublic) {
		t.Error("the server public key did not change although the private key did")
	}
	if runtime.GOOS != "windows" {
		if got := filePerm(t, path); got != 0o600 {
			t.Errorf("regenerated identity permission = %o, want 600", got)
		}
	}
}

// TestRegenerateNodeIdentityWithoutAFile 固定"新节点"路径：没有身份文件时直接生成，
// 且不产生一个空的备份。
func TestRegenerateNodeIdentityWithoutAFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "node-identity.json")

	backup, err := RegenerateNodeIdentityFile(path, NewNodeIdentity())
	if err != nil {
		t.Fatalf("RegenerateNodeIdentity: %v", err)
	}
	if backup != "" {
		t.Errorf("backup = %q, want empty", backup)
	}
	if _, err := os.Stat(path + vpn.BackupSuffix); !os.IsNotExist(err) {
		t.Errorf("a backup was written although there was nothing to replace: %v", err)
	}
	if _, err := LoadOrCreateNodeIdentity(path); err != nil {
		t.Errorf("the generated identity is not readable: %v", err)
	}
}

// TestLoadOrCreateNodeIdentityFileReportsInsteadOfGenerating 固定"只读"入口的契约：
// 坏文件返回 (nil, err) 而不是静默生成一份新的——那会换掉身份，而所有对端都要跟着改。
func TestLoadOrCreateNodeIdentityFileReportsInsteadOfGenerating(t *testing.T) {
	path := filepath.Join(t.TempDir(), "node-identity.json")
	if err := os.WriteFile(path, []byte("not-json"), 0o600); err != nil {
		t.Fatal(err)
	}

	ni, err := LoadOrCreateNodeIdentityFile(path)
	if err == nil {
		t.Fatal("LoadOrCreateNodeIdentityFile accepted a corrupt file")
	}
	if ni != nil {
		t.Errorf("identity = %+v, want nil on a corrupt file", ni)
	}
	if got, err := os.ReadFile(path); err != nil {
		t.Fatal(err)
	} else if string(got) != "not-json" {
		t.Errorf("the corrupt file was overwritten with %q", got)
	}
}

// TestRegenerateNodeIdentityFileRejectsIncompleteIdentity 固定"落盘前的自查"：一份缺字段的
// 身份比没有文件更难排查（tailcat 会在启动或首次访问对端时才失败，且错误信息不指向密钥
// 文件），因此宁可拒绝写入，也不能把它写进文件。
func TestRegenerateNodeIdentityFileRejectsIncompleteIdentity(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "node-identity.json")

	backup, err := RegenerateNodeIdentityFile(path, &NodeIdentity{})
	if err == nil {
		t.Fatal("RegenerateNodeIdentityFile wrote an empty identity")
	}
	if !strings.Contains(err.Error(), "node private key is missing") {
		t.Errorf("error %q should name the missing field", err)
	}
	if backup != "" {
		t.Errorf("backup = %q, want empty", backup)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("a file was written although the identity was rejected: %v", err)
	}
}

// TestRegenerateNodeIdentityFileKeepsTheOldFileOnRejection 固定同一个契约在有旧文件时的那
// 一半：自查失败不能碰旧身份（它是本节点唯一有效的地址来源）。
func TestRegenerateNodeIdentityFileKeepsTheOldFileOnRejection(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "node-identity.json")
	if _, err := LoadOrCreateNodeIdentity(path); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := RegenerateNodeIdentityFile(path, &NodeIdentity{}); err == nil {
		t.Fatal("RegenerateNodeIdentityFile accepted an empty identity")
	}
	if got, err := os.ReadFile(path); err != nil {
		t.Fatal(err)
	} else if string(got) != string(before) {
		t.Error("the existing identity was modified although the new one was rejected")
	}
	if _, err := os.Stat(path + vpn.BackupSuffix); !os.IsNotExist(err) {
		t.Errorf("a backup was written although nothing was replaced: %v", err)
	}
}
