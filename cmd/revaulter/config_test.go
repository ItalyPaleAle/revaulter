package main

import (
	"bytes"
	"encoding/base64"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"

	"github.com/italypaleale/revaulter/pkg/config"
	"github.com/italypaleale/revaulter/pkg/utils"
)

func TestValidateConfig(t *testing.T) {
	// Set initial variables in the viper global object
	defer utils.SetTestConfigs(getDefaultConfig())()
	defer utils.SetTestConfigs(map[string]any{
		config.KeyAzureClientId: "d196f679-da38-492c-946a-60ae8324e7f9",
		config.KeyAzureTenantId: "e440d651-3dcf-4c20-b147-96a2ff00ee25",
		config.KeyWebhookUrl:    "http://test.local",
	})()

	t.Run("succeeds with all required vars", func(t *testing.T) {
		err := validateConfig()
		require.NoError(t, err)
	})

	t.Run("fails without azureClientId", func(t *testing.T) {
		defer utils.SetTestConfigs(map[string]any{
			config.KeyAzureClientId: "",
		})()

		err := validateConfig()
		require.Error(t, err)
		require.ErrorContains(t, err, "'azureClientId' missing")
	})

	t.Run("fails without azureTenantId", func(t *testing.T) {
		defer utils.SetTestConfigs(map[string]any{
			config.KeyAzureTenantId: "",
		})()

		err := validateConfig()
		require.Error(t, err)
		require.ErrorContains(t, err, "'azureTenantId' missing")
	})

	t.Run("fails without webhookUrl", func(t *testing.T) {
		defer utils.SetTestConfigs(map[string]any{
			config.KeyWebhookUrl: "",
		})()

		err := validateConfig()
		require.Error(t, err)
		require.ErrorContains(t, err, "'webhookUrl' missing")
	})

	t.Run("fails with sessionTimeout too small", func(t *testing.T) {
		defer utils.SetTestConfigs(map[string]any{
			config.KeySessionTimeout: 100 * time.Millisecond,
		})()

		err := validateConfig()
		require.Error(t, err)
		require.ErrorContains(t, err, "'sessionTimeout' is invalid")
	})

	t.Run("fails with sessionTimeout too big", func(t *testing.T) {
		defer utils.SetTestConfigs(map[string]any{
			config.KeySessionTimeout: 3 * time.Hour,
		})()

		err := validateConfig()
		require.Error(t, err)
		require.ErrorContains(t, err, "'sessionTimeout' is invalid")
	})

	t.Run("fails with requestTimeout too small", func(t *testing.T) {
		defer utils.SetTestConfigs(map[string]any{
			config.KeyRequestTimeout: 100 * time.Millisecond,
		})()

		err := validateConfig()
		require.Error(t, err)
		require.ErrorContains(t, err, "'requestTimeout' is invalid")
	})
}

func TestEnsureTokenSigningKey(t *testing.T) {
	logs := &bytes.Buffer{}
	utils.SetAppLogger(&appLogger, logs)

	t.Run("tokenSigningKey present", func(t *testing.T) {
		defer utils.SetTestConfigs(map[string]any{
			config.KeyTokenSigningKey: "hello-world",
			// This will allow resetting it at the end of the test
			config.KeyInternalTokenSigningKey: "",
		})()

		err := ensureTokenSigningKey()
		require.NoError(t, err)
		require.Equal(t, "hello-world", viper.GetString(config.KeyInternalTokenSigningKey))
	})

	t.Run("tokenSigningKey not present", func(t *testing.T) {
		defer utils.SetTestConfigs(map[string]any{
			config.KeyTokenSigningKey: "",
			// This will allow resetting it at the end of the test
			config.KeyInternalTokenSigningKey: "",
		})()

		err := ensureTokenSigningKey()
		require.NoError(t, err)
		require.Len(t, viper.GetString(config.KeyInternalTokenSigningKey), 21)

		logsMsg := logs.String()
		require.Contains(t, logsMsg, "No 'tokenSigningKey' found in the configuration")
	})
}

func TestSetCookieKeys(t *testing.T) {
	logs := &bytes.Buffer{}
	utils.SetAppLogger(&appLogger, logs)

	t.Run("cookieEncryptionKey present", func(t *testing.T) {
		defer utils.SetTestConfigs(map[string]any{
			config.KeyCookieEncryptionKey: "some-key",
			// This will allow resetting the values at the end of the test
			config.KeyInternalCookieEncryptionKey: "",
			config.KeyInternalCookieSigningKey:    "",
		})()

		err := setCookieKeys()
		require.NoError(t, err)

		cekAny := viper.Get(config.KeyInternalCookieEncryptionKey)
		cskAny := viper.Get(config.KeyInternalCookieSigningKey)
		require.NotNil(t, cekAny)
		require.NotNil(t, cskAny)

		cek, ok := cekAny.(jwk.Key)
		require.True(t, ok)
		csk, ok := cskAny.(jwk.Key)
		require.True(t, ok)

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
		defer utils.SetTestConfigs(map[string]any{
			config.KeyCookieEncryptionKey: "",
			// This will allow resetting the values at the end of the test
			config.KeyInternalCookieEncryptionKey: "",
			config.KeyInternalCookieSigningKey:    "",
		})()

		err := setCookieKeys()
		require.NoError(t, err)

		cekAny := viper.Get(config.KeyInternalCookieEncryptionKey)
		cskAny := viper.Get(config.KeyInternalCookieSigningKey)
		require.NotNil(t, cekAny)
		require.NotNil(t, cskAny)

		cek, ok := cekAny.(jwk.Key)
		require.True(t, ok)
		csk, ok := cskAny.(jwk.Key)
		require.True(t, ok)

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
