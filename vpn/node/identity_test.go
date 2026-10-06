package vpnnode

import (
	"encoding/json"
	"os"
	"path/filepath"
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
	if got := filePerm(t, path); got != 0o600 {
		t.Errorf("key file permission = %o, want 600", got)
	}
	if got := filePerm(t, filepath.Dir(path)); got != 0o700 {
		t.Errorf("state dir permission = %o, want 700", got)
	}

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
