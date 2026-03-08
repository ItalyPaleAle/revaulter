package config

import (
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSetDBPayloadEncryptionKey(t *testing.T) {
	raw := []byte("supersecret-key-material")

	t.Run("parses base64", func(t *testing.T) {
		t.Cleanup(SetTestConfig(map[string]any{
			"dbPayloadEncryptionKey": base64.RawURLEncoding.EncodeToString(raw),
		}))
		err := config.SetDBPayloadEncryptionKey(nil)
		require.NoError(t, err)
		require.Len(t, config.GetDBPayloadEncryptionKey(), 32)
	})

	t.Run("parses hex", func(t *testing.T) {
		t.Cleanup(SetTestConfig(map[string]any{
			"dbPayloadEncryptionKey": hex.EncodeToString(raw),
		}))
		err := config.SetDBPayloadEncryptionKey(nil)
		require.NoError(t, err)
		require.Len(t, config.GetDBPayloadEncryptionKey(), 32)
	})

	t.Run("invalid", func(t *testing.T) {
		prev := config.DBPayloadEncryptionKey
		t.Cleanup(func() {
			config.DBPayloadEncryptionKey = prev
		})
		config.DBPayloadEncryptionKey = "%%%"
		err := config.SetDBPayloadEncryptionKey(nil)
		require.Error(t, err)
	})
}
