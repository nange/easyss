package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	serverconfig "github.com/nange/easyss/v3/server/config"
)

// newManualCertServer 构造一个手工证书模式的 Server：证书在测试内生成，Start
// 不访问 ACME，只需监听本地端口。
func newManualCertServer(t *testing.T, port int) *Server {
	t.Helper()
	certPath, keyPath := writeSelfSignedCert(t)
	srv, err := New(&serverconfig.FileConfig{
		Timeout: 5,
		Server: serverconfig.ServerConfig{
			Bind:     "127.0.0.1",
			Port:     port,
			Password: "test-password",
			CertPath: certPath,
			KeyPath:  keyPath,
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return srv
}

func writeSelfSignedCert(t *testing.T) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}

	dir := t.TempDir()
	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return certPath, keyPath
}

func freeTCPPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	defer ln.Close() //nolint:errcheck
	return ln.Addr().(*net.TCPAddr).Port
}

// TestStartAfterShutdownDoesNotListen 固定 Shutdown 先到的语义：Start 必须在
// 绑定端口之前放弃，而不是把已经被关闭的服务器重新拉起来。
func TestStartAfterShutdownDoesNotListen(t *testing.T) {
	// 这里用一个不可用端口：Start 若越过停止标志继续监听，用例会以绑定失败或超时失败。
	srv := newManualCertServer(t, 1)
	if err := srv.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	startDone := make(chan error, 1)
	go func() { startDone <- srv.Start() }()
	select {
	case err := <-startDone:
		if !errors.Is(err, http.ErrServerClosed) {
			t.Fatalf("Start after Shutdown = %v, want %v", err, http.ErrServerClosed)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Start after Shutdown kept listening")
	}
}

// TestStartShutdownConcurrentPublication 覆盖启动与关闭并发：启动路径发布的字段
// 必须在锁下交给 Shutdown，且无论哪一方先到，Start 都以 ErrServerClosed 返回。
func TestStartShutdownConcurrentPublication(t *testing.T) {
	const rounds = 10
	for i := range rounds {
		srv := newManualCertServer(t, freeTCPPort(t))

		startDone := make(chan error, 1)
		go func() { startDone <- srv.Start() }()
		shutdownDone := make(chan error, 1)
		go func() { shutdownDone <- srv.Shutdown(context.Background()) }()

		select {
		case err := <-shutdownDone:
			if err != nil {
				t.Fatalf("round #%d: Shutdown: %v", i, err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("round #%d: Shutdown did not return", i)
		}

		select {
		case err := <-startDone:
			if !errors.Is(err, http.ErrServerClosed) {
				t.Fatalf("round #%d: Start = %v, want %v", i, err, http.ErrServerClosed)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("round #%d: Start kept running after Shutdown", i)
		}
	}
}
