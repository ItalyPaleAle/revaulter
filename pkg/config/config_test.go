package config

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

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
		"secretKey":   "aGVsbG8",
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

	t.Run("fails when databaseDSN is set without secretKey", func(t *testing.T) {
		t.Cleanup(SetTestConfig(map[string]any{
			"databaseDSN": "sqlite://./test.db",
			"secretKey":   "",
		}))

		err := config.Validate(nil)
		require.Error(t, err)
		require.ErrorContains(t, err, "'secretKey' missing")
	})

	t.Run("fails when secretKey is set without databaseDSN", func(t *testing.T) {
		t.Cleanup(SetTestConfig(map[string]any{
			"databaseDSN": "",
			"secretKey":   "aGVsbG8",
		}))

		err := config.Validate(nil)
		require.Error(t, err)
		require.ErrorContains(t, err, "'databaseDSN' missing")
	})
}
