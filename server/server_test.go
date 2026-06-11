package server

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/caddyserver/certmagic"
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
