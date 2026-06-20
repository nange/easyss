package server

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/nange/easyss/v3/server/config"
	"github.com/stretchr/testify/require"
)

func TestCertmagicStoragePathForExecutable(t *testing.T) {
	exe := filepath.Join("tmp", "easyss", "easyss-server")
	require.Equal(t, filepath.Join("tmp", "easyss", "certmagic"), certmagicStoragePathForExecutable(exe))
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
