package config

import (
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSetSecretKey(t *testing.T) {
	raw := []byte("supersecret-key-material")

	t.Run("parses base64", func(t *testing.T) {
		t.Cleanup(SetTestConfig(map[string]any{
			"secretKey": base64.RawURLEncoding.EncodeToString(raw),
		}))
		err := config.SetSecretKey(nil)
		require.NoError(t, err)
		require.Len(t, config.GetSecretKey(), 32)
	})

	t.Run("parses hex", func(t *testing.T) {
		t.Cleanup(SetTestConfig(map[string]any{
			"secretKey": hex.EncodeToString(raw),
		}))
		err := config.SetSecretKey(nil)
		require.NoError(t, err)
		require.Len(t, config.GetSecretKey(), 32)
	})

	t.Run("invalid", func(t *testing.T) {
		prev := config.SecretKey
		t.Cleanup(func() {
			config.SecretKey = prev
		})
		config.SecretKey = "%%%"
		err := config.SetSecretKey(nil)
		require.Error(t, err)
	})
}
