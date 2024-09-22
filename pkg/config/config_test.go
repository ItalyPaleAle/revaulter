package config

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
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
		"azureClientId": "d196f679-da38-492c-946a-60ae8324e7f9",
		"azureTenantId": "e440d651-3dcf-4c20-b147-96a2ff00ee25",
		"webhookUrl":    "http://test.local",
	}))

	t.Run("succeeds with all required vars", func(t *testing.T) {
		err := config.Validate()
		require.NoError(t, err)
	})

	t.Run("fails without azureClientId", func(t *testing.T) {
		t.Cleanup(SetTestConfig(map[string]any{
			"azureClientId": "",
		}))

		err := config.Validate()
		require.Error(t, err)
		require.ErrorContains(t, err, "'azureClientId' missing")
	})

	t.Run("fails without azureTenantId", func(t *testing.T) {
		t.Cleanup(SetTestConfig(map[string]any{
			"azureTenantId": "",
		}))

		err := config.Validate()
		require.Error(t, err)
		require.ErrorContains(t, err, "'azureTenantId' missing")
	})

	t.Run("fails without webhookUrl", func(t *testing.T) {
		t.Cleanup(SetTestConfig(map[string]any{
			"webhookUrl": "",
		}))

		err := config.Validate()
		require.Error(t, err)
		require.ErrorContains(t, err, "'webhookUrl' missing")
	})

	t.Run("fails with sessionTimeout too small", func(t *testing.T) {
		t.Cleanup(SetTestConfig(map[string]any{
			"sessionTimeout": 100 * time.Millisecond,
		}))

		err := config.Validate()
		require.Error(t, err)
		require.ErrorContains(t, err, "'sessionTimeout' is invalid")
	})

	t.Run("fails with sessionTimeout too big", func(t *testing.T) {
		t.Cleanup(SetTestConfig(map[string]any{
			"sessionTimeout": 3 * time.Hour,
		}))

		err := config.Validate()
		require.Error(t, err)
		require.ErrorContains(t, err, "'sessionTimeout' is invalid")
	})

	t.Run("fails with requestTimeout too small", func(t *testing.T) {
		t.Cleanup(SetTestConfig(map[string]any{
			"requestTimeout": 100 * time.Millisecond,
		}))

		err := config.Validate()
		require.Error(t, err)
		require.ErrorContains(t, err, "'requestTimeout' is invalid")
	})
}

func TestSetTokenSigningKey(t *testing.T) {
	logs := &bytes.Buffer{}
	logger := slog.New(slog.NewTextHandler(logs, nil))

	t.Run("tokenSigningKey present", func(t *testing.T) {
		t.Cleanup(SetTestConfig(map[string]any{
			"tokenSigningKey": "hello-world",
		}))

		err := config.SetTokenSigningKey(logger)
		require.NoError(t, err)
		assert.Equal(t, "b8cf67b06159c291d6cc1e27b10cddeab93f48f444995f4b0fb886e3ea75d422", hex.EncodeToString(config.GetTokenSigningKey()))
	})

	t.Run("tokenSigningKey not present", func(t *testing.T) {
		t.Cleanup(SetTestConfig(map[string]any{
			"tokenSigningKey": "",
		}))

		err := config.SetTokenSigningKey(logger)
		require.NoError(t, err)
		val := config.GetTokenSigningKey()
		require.Len(t, val, 32)

		logsMsg := logs.String()
		require.Contains(t, logsMsg, "No 'tokenSigningKey' found in the configuration")

		// Should be different every time
		err = config.SetTokenSigningKey(logger)
		require.NoError(t, err)
		assert.NotEqual(t, val, config.GetTokenSigningKey())
	})
}

func TestSetCookieKeys(t *testing.T) {
	t.Run("cookieEncryptionKey present", func(t *testing.T) {
		t.Cleanup(SetTestConfig(map[string]any{
			"cookieEncryptionKey": "some-key",
		}))

		err := config.SetCookieKeys(nil)
		require.NoError(t, err)

		cek := config.GetCookieEncryptionKey()
		csk := config.GetCookieSigningKey()
		require.NotNil(t, cek)
		require.NotNil(t, csk)

		var cekRaw, cskRaw []byte
		err = cek.Raw(&cekRaw)
		require.NoError(t, err)
		err = csk.Raw(&cskRaw)
		require.NoError(t, err)

		require.Equal(t, "l8LxoY6e2c/nZigC7n0cJg", base64.RawStdEncoding.EncodeToString(cekRaw))
		require.Equal(t, "HyY6TBU8Qwd2yXspvM0zDEPt/Sz7DEcTdjvEHNgENxw", base64.RawStdEncoding.EncodeToString(cskRaw))

		require.Equal(t, "o2Bqhc6QPigj8GwA", cek.KeyID())
		require.Equal(t, "o2Bqhc6QPigj8GwA", csk.KeyID())
	})

	t.Run("cookieEncryptionKey no present", func(t *testing.T) {
		t.Cleanup(SetTestConfig(map[string]any{
			"cookieEncryptionKey": "",
		}))

		err := config.SetCookieKeys(nil)
		require.NoError(t, err)

		cek := config.GetCookieEncryptionKey()
		csk := config.GetCookieSigningKey()
		require.NotNil(t, cek)
		require.NotNil(t, csk)

		var cekRaw, cskRaw []byte
		err = cek.Raw(&cekRaw)
		require.NoError(t, err)
		err = csk.Raw(&cskRaw)
		require.NoError(t, err)

		require.Len(t, cekRaw, 16)
		require.Len(t, cskRaw, 32)

		require.NotEmpty(t, cek.KeyID())
		require.NotEmpty(t, csk.KeyID())
	})
}
