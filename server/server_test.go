package server

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
	sharedconfig "github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/server/config"
	"github.com/stretchr/testify/require"
)

func TestCertmagicStoragePathForExecutable(t *testing.T) {
	exe := filepath.Join("tmp", "easyss", "easyss-server")
	require.Equal(t, filepath.Join("tmp", "easyss", "certmagic"), certmagicStoragePathForExecutable(exe))
}

func TestNewTransportProtocolsValidation(t *testing.T) {
	require.NoError(t, mustNewServer(t, nil))
	require.NoError(t, mustNewServer(t, []string{"h2"}))
	require.Error(t, mustNewServer(t, []string{"h3"}))
	require.Error(t, mustNewServer(t, []string{"h2", "h3"}))
}

func mustNewServer(t *testing.T, protocols []string) error {
	t.Helper()
	_, err := New(&config.ServerConfig{
		Transport: config.TransportConfig{Protocols: protocols},
	})
	return err
}

func TestShouldRetryFreshCertificate(t *testing.T) {
	require.True(t, shouldRetryFreshCertificate(errString("Could not validate ARI 'replaces' field")))
	require.True(t, shouldRetryFreshCertificate(errString("Requested certificate was not found")))
	require.False(t, shouldRetryFreshCertificate(errString("dial tcp: i/o timeout")))
}

func TestCleanCertmagicDomainAssets(t *testing.T) {
	storage := &certmagic.FileStorage{Path: t.TempDir()}
	domain := "example.com"
	issuerKey := (&certmagic.ACMEIssuer{CA: certmagic.DefaultACME.CA}).IssuerKey()

	keys := []string{
		certmagic.StorageKeys.SiteCert(issuerKey, domain),
		certmagic.StorageKeys.SitePrivateKey(issuerKey, domain),
		certmagic.StorageKeys.SiteMeta(issuerKey, domain),
	}
	for _, key := range keys {
		require.NoError(t, storage.Store(context.Background(), key, []byte("test")))
		require.True(t, storage.Exists(context.Background(), key))
	}

	require.NoError(t, cleanCertmagicDomainAssets(context.Background(), storage, domain))
	for _, key := range keys {
		require.False(t, storage.Exists(context.Background(), key))
	}
}

type errString string

func (e errString) Error() string { return string(e) }

func TestRandomEmail(t *testing.T) {
	email := randomEmail()
	matched, err := regexp.MatchString(`^admin-[0-9a-f]{16}@example\.com$`, email)
	require.NoError(t, err)
	require.True(t, matched, "unexpected email format: %s", email)
}

func TestFindExistingACMEEmail(t *testing.T) {
	tmpDir := t.TempDir()
	storagePath := filepath.Join(tmpDir, "certmagic")

	// Create directory structure mimicking certmagic:
	// certmagic/acme/acme-v02.api.letsencrypt.org-directory/users/old@example.com/
	// certmagic/acme/acme-v02.api.letsencrypt.org-directory/users/new@example.com/
	usersPath := filepath.Join(storagePath, "acme", "acme-v02.api.letsencrypt.org-directory", "users")
	oldEmailDir := filepath.Join(usersPath, "old@example.com")
	newEmailDir := filepath.Join(usersPath, "new@example.com")

	require.NoError(t, os.MkdirAll(oldEmailDir, 0700))
	require.NoError(t, os.MkdirAll(newEmailDir, 0700))

	// Ensure old email has earlier modification time
	oldTime := time.Now().Add(-1 * time.Hour)
	require.NoError(t, os.Chtimes(oldEmailDir, oldTime, oldTime))

	result := findExistingACMEEmail(storagePath)
	require.Equal(t, "old@example.com", result)
}

func TestFindExistingACMEEmail_Empty(t *testing.T) {
	tmpDir := t.TempDir()

	// No acme directory at all
	result := findExistingACMEEmail(tmpDir)
	require.Equal(t, "", result)
}

func TestFindExistingACMEEmail_NoUsers(t *testing.T) {
	tmpDir := t.TempDir()

	// acme directory exists but no users subdirectory
	acmePath := filepath.Join(tmpDir, "acme", "some-ca")
	require.NoError(t, os.MkdirAll(acmePath, 0700))

	result := findExistingACMEEmail(tmpDir)
	require.Equal(t, "", result)
}

func TestResolveEmail_Configured(t *testing.T) {
	s := &Server{
		cfg: &config.ServerConfig{
			Email: "user@example.com",
		},
	}
	s.resolveEmail(t.TempDir())
	require.Equal(t, "user@example.com", s.cfg.Email)
}

func TestResolveEmail_Reuse(t *testing.T) {
	tmpDir := t.TempDir()
	storagePath := filepath.Join(tmpDir, "certmagic")

	// Create existing email on disk
	usersPath := filepath.Join(storagePath, "acme", "acme-v02.api.letsencrypt.org-directory", "users")
	existingEmail := "reused@example.com"
	require.NoError(t, os.MkdirAll(filepath.Join(usersPath, existingEmail), 0700))

	s := &Server{
		cfg: &config.ServerConfig{
			Email: "", // not configured
		},
	}
	s.resolveEmail(storagePath)
	require.Equal(t, existingEmail, s.cfg.Email)
}

func TestResolveEmail_Generated(t *testing.T) {
	s := &Server{
		cfg: &config.ServerConfig{
			Email: "",
		},
	}
	s.resolveEmail(t.TempDir())

	matched, err := regexp.MatchString(`^admin-[0-9a-f]{16}@example\.com$`, s.cfg.Email)
	require.NoError(t, err)
	require.True(t, matched, "unexpected generated email format: %s", s.cfg.Email)
}

// TestBuildHTTPServerUploadFlowControl pins the upload-side flow-control
// windows with literal lower bounds (not the constants themselves, so a
// regression that shrinks the constants also fails this test): a single
// upload stream is capped at roughly window/RTT, so the per-stream window
// must be at least 1MB (~26Mbps on a 300ms link) and the connection window
// at least 2MB.
func TestBuildHTTPServerUploadFlowControl(t *testing.T) {
	srv := buildHTTPServer(&config.ServerConfig{Listen: ":443"}, nil, http.NewServeMux(), 30*time.Second)
	require.NotNil(t, srv.HTTP2)
	require.GreaterOrEqual(t, srv.HTTP2.MaxReceiveBufferPerStream, 1<<20,
		"per-stream upload window must be >= 1MB")
	require.GreaterOrEqual(t, srv.HTTP2.MaxReceiveBufferPerConnection, 2<<20,
		"connection upload window must be >= 2MB")
}

// TestServerUploadFlowControlWindowsOnWire verifies the windows the server
// actually advertises to a client: SETTINGS_INITIAL_WINDOW_SIZE carries the
// per-stream upload window, and a connection-level WINDOW_UPDATE grants the
// connection window beyond the RFC 7540 initial 65535 bytes. The stdlib
// server queues its SETTINGS and flushes them as soon as the client preface
// arrives, so the frames are immediately readable after the preface.
func TestServerUploadFlowControlWindowsOnWire(t *testing.T) {
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	ts.EnableHTTP2 = true
	ts.Config.Protocols = &http.Protocols{}
	ts.Config.Protocols.SetHTTP2(true)
	ts.Config.HTTP2 = &http.HTTP2Config{
		MaxReceiveBufferPerConnection: sharedconfig.HTTP2ServerReceiveBufferPerConnection,
		MaxReceiveBufferPerStream:     sharedconfig.HTTP2ServerReceiveBufferPerStream,
	}
	ts.StartTLS()
	t.Cleanup(ts.Close)

	conn, err := tls.Dial("tcp", ts.Listener.Addr().String(), &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // test-only self-signed cert
		NextProtos:         []string{"h2"},
	})
	require.NoError(t, err)
	defer conn.Close() //nolint:errcheck
	require.Equal(t, "h2", conn.ConnectionState().NegotiatedProtocol)

	// Send the HTTP/2 client preface: the server flushes its SETTINGS and
	// connection WINDOW_UPDATE once it reads it.
	_, err = conn.Write([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"))
	require.NoError(t, err)
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))

	const (
		frameSettings   = 0x4
		frameWindowUpd  = 0x8
		settingInitWin  = 0x4
		initialConnWin  = 65535 // RFC 7540 initial connection window
		maxFramesToRead = 16
	)
	var streamWindow, connWindow = 0, initialConnWin
	for range maxFramesToRead {
		var hdr [9]byte
		_, err := io.ReadFull(conn, hdr[:])
		require.NoError(t, err)
		length := int(hdr[0])<<16 | int(hdr[1])<<8 | int(hdr[2])
		streamID := binary.BigEndian.Uint32(hdr[5:9]) & 0x7fffffff

		payload := make([]byte, length)
		_, err = io.ReadFull(conn, payload)
		require.NoError(t, err)

		switch hdr[3] {
		case frameSettings:
			for len(payload) >= 6 {
				id := binary.BigEndian.Uint16(payload[:2])
				val := binary.BigEndian.Uint32(payload[2:6])
				payload = payload[6:]
				if id == settingInitWin {
					streamWindow = int(val)
				}
			}
		case frameWindowUpd:
			if streamID == 0 && len(payload) == 4 {
				connWindow += int(binary.BigEndian.Uint32(payload))
			}
		}
		if streamWindow > 0 && connWindow > initialConnWin {
			break
		}
	}

	require.GreaterOrEqual(t, streamWindow, 1<<20,
		"advertised per-stream upload window must be >= 1MB")
	require.GreaterOrEqual(t, connWindow, 2<<20,
		"connection upload window must be >= 2MB")
}
