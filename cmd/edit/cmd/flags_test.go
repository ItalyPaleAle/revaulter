package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/italypaleale/revaulter/internal/clienttest"
	"github.com/italypaleale/revaulter/pkg/revaulter"
)

func TestCommonFlagsRequestKey(t *testing.T) {
	const jwt = "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ4In0.c2ln"

	writeKeyFile := func(t *testing.T, content string) string {
		t.Helper()

		path := filepath.Join(t.TempDir(), "request-key")
		err := os.WriteFile(path, []byte(content), 0o600)
		require.NoError(t, err)
		return path
	}

	// Clear the environment so the host's variables can't leak into the tests
	clearEnv := func(t *testing.T) {
		t.Setenv(envServer, "")
		t.Setenv(envRequestKey, "")
		t.Setenv(envRequestKeyFile, "")
		t.Setenv(envUserID, "")
	}

	// Validate the flags with a server set
	// The TLS and trust store flags keep their defaults, so Validate never asks for confirmation
	validate := func(f *commonFlags) error {
		f.Server = "https://revaulter.example.com"
		return f.Validate()
	}

	t.Run("reads the key from --request-key-file", func(t *testing.T) {
		clearEnv(t)
		f := &commonFlags{
			RequestKeyFile: writeKeyFile(t, "rvk_fromfile\n"),
		}
		err := validate(f)
		require.NoError(t, err)
		require.Equal(t, "rvk_fromfile", f.RequestKey)
	})

	t.Run("reads the key from the file in the environment", func(t *testing.T) {
		clearEnv(t)
		t.Setenv(
			envRequestKeyFile, writeKeyFile(t, "rvk_fromenvfile"),
		)
		f := &commonFlags{}
		err := validate(f)
		require.NoError(t, err)
		require.Equal(t, "rvk_fromenvfile", f.RequestKey)
	})

	t.Run("flags take precedence over the environment", func(t *testing.T) {
		clearEnv(t)
		t.Setenv(envRequestKey, "rvk_fromenv")
		f := &commonFlags{
			RequestKeyFile: writeKeyFile(t, "rvk_fromfile"),
		}
		err := validate(f)
		require.NoError(t, err)
		require.Equal(t, "rvk_fromfile", f.RequestKey)
	})

	t.Run("rejects both flags", func(t *testing.T) {
		clearEnv(t)
		f := &commonFlags{
			RequestKey:     "rvk_inline",
			RequestKeyFile: writeKeyFile(t, "rvk_fromfile"),
		}
		require.ErrorContains(t, validate(f), "mutually exclusive")
	})

	t.Run("rejects both environment variables", func(t *testing.T) {
		clearEnv(t)
		t.Setenv(envRequestKey, "rvk_fromenv")
		t.Setenv(envRequestKeyFile, writeKeyFile(t, "rvk_fromfile"))
		err := validate(&commonFlags{})
		require.ErrorContains(t, err, "mutually exclusive")
	})

	t.Run("requires a key", func(t *testing.T) {
		clearEnv(t)
		err := validate(&commonFlags{})
		require.ErrorContains(t, err, "--request-key or --request-key-file is required")
	})

	t.Run("reports an invalid file", func(t *testing.T) {
		clearEnv(t)
		f := &commonFlags{
			RequestKeyFile: filepath.Join(t.TempDir(), "missing"),
		}
		require.ErrorContains(t, validate(f), "invalid --request-key-file")
	})

	t.Run("requires the user ID with an OIDC token from a file", func(t *testing.T) {
		clearEnv(t)
		f := &commonFlags{
			RequestKeyFile: writeKeyFile(t, jwt),
		}
		require.ErrorContains(t, validate(f), "--user-id is required")

		f = &commonFlags{
			RequestKeyFile: writeKeyFile(t, jwt),
			UserID:         "user-1",
		}
		err := validate(f)
		require.NoError(t, err)
		require.Equal(t, jwt, f.RequestKey)
	})
}

func TestCommonFlagsRenewedTokenFile(t *testing.T) {
	t.Setenv(envServer, "")
	t.Setenv(envRequestKey, "")
	t.Setenv(envRequestKeyFile, "")
	t.Setenv(envUserID, "")

	srv := clienttest.NewServer(t)
	path := filepath.Join(t.TempDir(), "token")
	err := os.WriteFile(path, []byte(clienttest.OIDCToken), 0o600)
	require.NoError(t, err)

	f := &commonFlags{
		Server:         srv.URL,
		RequestKeyFile: path,
		UserID:         clienttest.UserID,
		NoTrustStore:   true,
	}
	err = f.Validate()
	require.NoError(t, err)

	client, err := f.newClient(testLogger())
	require.NoError(t, err)

	_, err = client.SigningPublicKey(t.Context(), "notes", revaulter.AlgorithmES256)
	require.NoError(t, err)

	// The token is renewed while the file is being edited, and the server stops accepting the previous one
	err = os.WriteFile(path, []byte(clienttest.RenewedOIDCToken), 0o600)
	require.NoError(t, err)
	srv.SetOIDCToken(clienttest.RenewedOIDCToken)

	_, err = client.SigningPublicKey(t.Context(), "notes", revaulter.AlgorithmES256)
	require.NoError(t, err)
}
