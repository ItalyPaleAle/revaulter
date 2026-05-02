package healthcheck

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/italypaleale/revaulter/pkg/config"
)

func TestRunHTTPServer(t *testing.T) {
	srv := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/healthz" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		}),
	)
	defer srv.Close()

	err := Run([]string{
		"--server", srv.URL,
	})
	require.NoError(t, err)
}

func TestRunTLSServer(t *testing.T) {
	srv := httptest.NewTLSServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/healthz" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		}),
	)
	defer srv.Close()

	err := Run([]string{
		"--server", srv.URL,
	})
	require.NoError(t, err)
}

func TestRunReturnsErrorOnTimeout(t *testing.T) {
	srv := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Sleep for longer than the 5ms timeout
			time.Sleep(20 * time.Millisecond)

			if r.URL.Path != "/healthz" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		}),
	)
	defer srv.Close()

	err := Run([]string{
		"--server", srv.URL,
		"--timeout", "5ms",
	})
	require.Error(t, err)
	require.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestRunReturnsErrorOnFailureStatus(t *testing.T) {
	srv := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
		}),
	)
	defer srv.Close()

	err := Run([]string{
		"--server", srv.URL,
	})
	require.Error(t, err)
	require.ErrorContains(t, err, "status code 503")
}

func TestDefaultServerUsesHTTPWithoutTLS(t *testing.T) {
	cfg := config.GetDefaultConfig()
	cfg.Port = 9443

	serverURL := defaultServer(cfg)
	require.Equal(t, "http://localhost:9443", serverURL)
}

func TestDefaultServerUsesHTTPSWhenTLSFilesAreConfigured(t *testing.T) {
	tempDir := t.TempDir()

	// The actual contents of the files doesn't matter
	err := os.WriteFile(filepath.Join(tempDir, config.TLSCertFile), []byte("foo"), 0o600)
	require.NoError(t, err)
	err = os.WriteFile(filepath.Join(tempDir, config.TLSKeyFile), []byte("foo"), 0o600)
	require.NoError(t, err)

	cfg := config.GetDefaultConfig()
	cfg.Port = 8443
	cfg.SetLoadedConfigPath(filepath.Join(tempDir, "config.yaml"))

	serverURL := defaultServer(cfg)
	require.Equal(t, "https://localhost:8443", serverURL)
}
