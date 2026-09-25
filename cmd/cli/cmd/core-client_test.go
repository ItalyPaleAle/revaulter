package cmd

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/italypaleale/revaulter/internal/clienttest"
	"github.com/italypaleale/revaulter/internal/protocolv2"
)

func TestNewCoreClientCredentials(t *testing.T) {
	const token = "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ4In0.c2ln"
	log := slog.New(slog.DiscardHandler)

	t.Run("request key", func(t *testing.T) {
		_, err := newCoreClient(log, &trustCmd{Server: "https://revaulter.example.com", RequestKey: "rvk_abc"}, nil)
		require.NoError(t, err)
	})

	t.Run("OIDC token with user ID", func(t *testing.T) {
		_, err := newCoreClient(log, &trustCmd{Server: "https://revaulter.example.com", RequestKey: token, UserID: "user-1"}, nil)
		require.NoError(t, err)
	})

	t.Run("OIDC token without user ID", func(t *testing.T) {
		_, err := newCoreClient(log, &trustCmd{Server: "https://revaulter.example.com", RequestKey: token}, nil)
		require.ErrorContains(t, err, "--user-id is required")
	})
}

func TestNewCoreClientRenewedTokenFile(t *testing.T) {
	srv := clienttest.NewServer(t)
	path := filepath.Join(t.TempDir(), "token")
	err := os.WriteFile(path, []byte(clienttest.OIDCToken), 0o600)
	require.NoError(t, err)

	// The ssh-agent command builds its client once from these flags, then uses it for every signature
	flags := &v2OperationFlagsBase{
		Server:         srv.URL,
		RequestKeyFile: path,
		UserID:         clienttest.UserID,
		KeyLabel:       "ssh",
		NoTrustStore:   true,
	}
	err = flags.Validate()
	require.NoError(t, err)

	client, err := newCoreClient(slog.New(slog.DiscardHandler), flags, nil)
	require.NoError(t, err)

	_, err = client.SigningPublicKey(t.Context(), "ssh", protocolv2.SigningAlgES256)
	require.NoError(t, err)

	// The token is renewed, and the server stops accepting the previous one
	err = os.WriteFile(path, []byte(clienttest.RenewedOIDCToken), 0o600)
	require.NoError(t, err)
	srv.SetOIDCToken(clienttest.RenewedOIDCToken)

	_, err = client.SigningPublicKey(t.Context(), "ssh", protocolv2.SigningAlgES256)
	require.NoError(t, err)
}
