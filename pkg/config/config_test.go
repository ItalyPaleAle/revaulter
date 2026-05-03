package config

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testSecretKey = "0123456789abcdefghij0123456789"

func TestValidateConfig(t *testing.T) {
	// Set initial variables in the global object
	oldConfig := config
	config = GetDefaultConfig()
	t.Cleanup(func() {
		config = oldConfig
	})

	t.Cleanup(SetTestConfig(map[string]any{
		"webhookUrl":  "http://test.local",
		"databaseDSN": "sqlite://./test.db",
		"secretKey":   testSecretKey,
	}))

	t.Run("succeeds with all required vars", func(t *testing.T) {
		err := config.Validate(nil)
		require.NoError(t, err)
	})

	t.Run("fails without databaseDSN", func(t *testing.T) {
		t.Cleanup(SetTestConfig(map[string]any{
			"databaseDSN": "",
		}))

		err := config.Validate(nil)
		require.Error(t, err)
		require.ErrorContains(t, err, "'databaseDSN' missing")
	})

	t.Run("fails without webhookUrl", func(t *testing.T) {
		t.Cleanup(SetTestConfig(map[string]any{
			"webhookUrl": "",
		}))

		err := config.Validate(nil)
		require.Error(t, err)
		require.ErrorContains(t, err, "'webhookUrl' missing")
	})

	t.Run("fails with sessionTimeout too small", func(t *testing.T) {
		t.Cleanup(SetTestConfig(map[string]any{
			"sessionTimeout": 100 * time.Millisecond,
		}))

		err := config.Validate(nil)
		require.Error(t, err)
		require.ErrorContains(t, err, "'sessionTimeout' is invalid")
	})

	t.Run("fails with sessionTimeout too big", func(t *testing.T) {
		t.Cleanup(SetTestConfig(map[string]any{
			"sessionTimeout": 3 * time.Hour,
		}))

		err := config.Validate(nil)
		require.Error(t, err)
		require.ErrorContains(t, err, "'sessionTimeout' is invalid")
	})

	t.Run("fails with requestTimeout too small", func(t *testing.T) {
		t.Cleanup(SetTestConfig(map[string]any{
			"requestTimeout": 100 * time.Millisecond,
		}))

		err := config.Validate(nil)
		require.Error(t, err)
		require.ErrorContains(t, err, "'requestTimeout' is invalid")
	})

	t.Run("fails when secretKey is empty", func(t *testing.T) {
		t.Cleanup(SetTestConfig(map[string]any{
			"secretKey": "",
		}))

		err := config.Validate(nil)
		require.Error(t, err)
		require.ErrorContains(t, err, "'secretKey' missing")
	})

	t.Run("fails when databaseDSN is empty", func(t *testing.T) {
		t.Cleanup(SetTestConfig(map[string]any{
			"databaseDSN": "",
		}))

		err := config.Validate(nil)
		require.Error(t, err)
		require.ErrorContains(t, err, "'databaseDSN' missing")
	})

	t.Run("fails when secretKey is too short", func(t *testing.T) {
		t.Cleanup(SetTestConfig(map[string]any{
			"secretKey": "too-short-secret",
		}))

		err := config.Validate(nil)
		require.Error(t, err)
		require.ErrorContains(t, err, "secret key is too short")
	})

	t.Run("fails when sessionSigningKey is too short", func(t *testing.T) {
		t.Cleanup(SetTestConfig(map[string]any{
			"sessionSigningKey": "too-short-session",
		}))

		err := config.Validate(nil)
		require.Error(t, err)
		require.ErrorContains(t, err, "session signing key is too short")
	})
}

func TestSetSecretKey(t *testing.T) {
	t.Run("fails with an empty secret", func(t *testing.T) {
		cfg := &Config{}

		err := cfg.SetSecretKey(nil)
		require.Error(t, err)
		require.ErrorContains(t, err, "secret key value is empty")
	})

	t.Run("derives the prf salt and generates token signing key when unset", func(t *testing.T) {
		cfg := &Config{
			SecretKey: testSecretKey,
		}

		err := cfg.SetSecretKey(nil)
		require.NoError(t, err)

		assert.Equal(t, "5VgVFp_QTW5WNbVFLxgANw", cfg.GetPRFSalt())

		tokenSigningKey := cfg.internal.tokenSigningKey
		require.NotNil(t, tokenSigningKey)

		octets, ok := tokenSigningKey.Octets()
		require.True(t, ok)
		require.Len(t, octets, 32)
		require.NotEqual(t, make([]byte, 32), octets, "key was not empty")

		kid, ok := tokenSigningKey.KeyID()
		require.True(t, ok)
		require.NotEmpty(t, kid)
	})

	t.Run("uses a separate session signing key when configured", func(t *testing.T) {
		cfg := &Config{
			SecretKey:         testSecretKey,
			SessionSigningKey: "session-signing-key-0123456789",
		}

		err := cfg.SetSecretKey(nil)
		require.NoError(t, err)

		assert.Equal(t, "5VgVFp_QTW5WNbVFLxgANw", cfg.GetPRFSalt())

		tokenSigningKey := cfg.internal.tokenSigningKey
		require.NotNil(t, tokenSigningKey)

		octets, ok := tokenSigningKey.Octets()
		require.True(t, ok)
		require.Equal(t, "961433ce046aad4e2618d22187ed0f450b4b686de4ad90ed9d0e5a2e0cba3046", hex.EncodeToString(octets))

		kid, ok := tokenSigningKey.KeyID()
		require.True(t, ok)
		require.Equal(t, "CPJB5Nriy3r1JzMy", kid)
	})
}
