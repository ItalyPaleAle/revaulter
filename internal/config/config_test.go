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

	t.Run("succeeds without webhookUrl", func(t *testing.T) {
		t.Cleanup(SetTestConfig(map[string]any{
			"webhookUrl": "",
		}))

		err := config.Validate(nil)
		require.NoError(t, err)
	})

	t.Run("fails when webhookUrl has a disallowed scheme", func(t *testing.T) {
		t.Cleanup(SetTestConfig(map[string]any{
			"webhookUrl": "ftp://test.local",
		}))

		err := config.Validate(nil)
		require.Error(t, err)
		require.ErrorContains(t, err, "'webhookUrl' has disallowed scheme")
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

func TestValidateAuditStream(t *testing.T) {
	// Set initial variables in the global object
	oldConfig := config
	config = GetDefaultConfig()
	t.Cleanup(func() {
		config = oldConfig
	})

	t.Cleanup(SetTestConfig(map[string]any{
		"databaseDSN": "sqlite://./test.db",
		"secretKey":   testSecretKey,
	}))

	t.Run("every option is inert while the stream is disabled", func(t *testing.T) {
		t.Cleanup(SetTestConfig(map[string]any{
			"auditStreamUrl":        "",
			"auditStreamFormat":     "nonsense",
			"auditStreamBatchSize":  99999,
			"auditStreamEventTypes": []string{"not a valid entry"},
		}))

		err := config.Validate(nil)
		require.NoError(t, err)
	})

	t.Run("fails when auditStreamUrl has a disallowed scheme", func(t *testing.T) {
		t.Cleanup(SetTestConfig(map[string]any{
			"auditStreamUrl": "ftp://collector.local",
		}))

		err := config.Validate(nil)
		require.Error(t, err)
		require.ErrorContains(t, err, "'auditStreamUrl' has disallowed scheme")
	})

	t.Run("applies the defaults", func(t *testing.T) {
		t.Cleanup(SetTestConfig(map[string]any{
			"auditStreamUrl": "https://collector.local/ingest",
		}))

		err := config.Validate(nil)
		require.NoError(t, err)
		assert.Equal(t, 100, config.AuditStreamBatchSize)
		assert.Equal(t, 10*time.Second, config.AuditStreamFlushInterval)
	})

	t.Run("normalizes the format", func(t *testing.T) {
		t.Cleanup(SetTestConfig(map[string]any{
			"auditStreamUrl":    "https://collector.local/ingest",
			"auditStreamFormat": "NDJSON",
		}))

		err := config.Validate(nil)
		require.NoError(t, err)
		assert.Equal(t, "ndjson", config.AuditStreamFormat)
	})

	t.Run("fails on an unsupported format", func(t *testing.T) {
		t.Cleanup(SetTestConfig(map[string]any{
			"auditStreamUrl":    "https://collector.local/ingest",
			"auditStreamFormat": "msgpack",
		}))

		err := config.Validate(nil)
		require.Error(t, err)
		require.ErrorContains(t, err, "'auditStreamFormat' is invalid")
	})

	t.Run("fails on an out-of-range batch size", func(t *testing.T) {
		t.Cleanup(SetTestConfig(map[string]any{
			"auditStreamUrl":       "https://collector.local/ingest",
			"auditStreamBatchSize": 1001,
		}))

		err := config.Validate(nil)
		require.Error(t, err)
		require.ErrorContains(t, err, "'auditStreamBatchSize' is invalid")
	})

	t.Run("fails on an out-of-range flush interval", func(t *testing.T) {
		t.Cleanup(SetTestConfig(map[string]any{
			"auditStreamUrl":           "https://collector.local/ingest",
			"auditStreamFlushInterval": "10m",
		}))

		err := config.Validate(nil)
		require.Error(t, err)
		require.ErrorContains(t, err, "'auditStreamFlushInterval' is invalid")
	})

	t.Run("normalizes the event type filter", func(t *testing.T) {
		t.Cleanup(SetTestConfig(map[string]any{
			"auditStreamUrl":        "https://collector.local/ingest",
			"auditStreamEventTypes": []string{" Request.* ", "auth.login_finish"},
		}))

		err := config.Validate(nil)
		require.NoError(t, err)
		assert.Equal(t, []string{"request.*", "auth.login_finish"}, config.AuditStreamEventTypes)
	})

	t.Run("fails on a malformed event type filter", func(t *testing.T) {
		t.Cleanup(SetTestConfig(map[string]any{
			"auditStreamUrl":        "https://collector.local/ingest",
			"auditStreamEventTypes": []string{"request"},
		}))

		err := config.Validate(nil)
		require.Error(t, err)
		require.ErrorContains(t, err, "'auditStreamEventTypes' contains an invalid entry")
	})
}

func TestValidateFrancis(t *testing.T) {
	// Set initial variables in the global object
	oldConfig := config
	config = GetDefaultConfig()
	t.Cleanup(func() {
		config = oldConfig
	})

	t.Cleanup(SetTestConfig(map[string]any{
		"databaseDSN": "sqlite://./test.db",
		"secretKey":   testSecretKey,
	}))

	t.Run("succeeds with the default peer address", func(t *testing.T) {
		err := config.Validate(nil)
		require.NoError(t, err)
		assert.True(t, config.FrancisPeerAddressIsLoopback())
	})

	t.Run("fails without a peer address", func(t *testing.T) {
		t.Cleanup(SetTestConfig(map[string]any{
			"francisPeerAddress": "",
		}))

		err := config.Validate(nil)
		require.Error(t, err)
		require.ErrorContains(t, err, "'francisPeerAddress' is required")
	})

	t.Run("fails when the peer address has no port", func(t *testing.T) {
		t.Cleanup(SetTestConfig(map[string]any{
			"francisPeerAddress": "127.0.0.1",
		}))

		err := config.Validate(nil)
		require.Error(t, err)
		require.ErrorContains(t, err, "'francisPeerAddress' is invalid")
	})

	t.Run("fails when the peer address has an invalid port", func(t *testing.T) {
		t.Cleanup(SetTestConfig(map[string]any{
			"francisPeerAddress": "127.0.0.1:0",
		}))

		err := config.Validate(nil)
		require.Error(t, err)
		require.ErrorContains(t, err, "'francisPeerAddress' is invalid")
	})

	t.Run("fails when the bind port is out of range", func(t *testing.T) {
		t.Cleanup(SetTestConfig(map[string]any{
			"francisBindPort": 70000,
		}))

		err := config.Validate(nil)
		require.Error(t, err)
		require.ErrorContains(t, err, "'francisBindPort' is invalid")
	})

	t.Run("requires a session signing key with a non-loopback peer address", func(t *testing.T) {
		t.Cleanup(SetTestConfig(map[string]any{
			"francisPeerAddress": "10.0.0.5:7571",
		}))

		assert.False(t, config.FrancisPeerAddressIsLoopback())

		err := config.Validate(nil)
		require.Error(t, err)
		require.ErrorContains(t, err, "'sessionSigningKey' is required")
	})

	t.Run("succeeds with a non-loopback peer address and a session signing key", func(t *testing.T) {
		t.Cleanup(SetTestConfig(map[string]any{
			"francisPeerAddress": "revaulter-1.internal:7571",
			"sessionSigningKey":  "session-signing-key-0123456789",
		}))

		err := config.Validate(nil)
		require.NoError(t, err)
	})

	t.Run("treats localhost as loopback", func(t *testing.T) {
		t.Cleanup(SetTestConfig(map[string]any{
			"francisPeerAddress": "localhost:7571",
		}))

		assert.True(t, config.FrancisPeerAddressIsLoopback())

		err := config.Validate(nil)
		require.NoError(t, err)
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

	t.Run("derives the Francis cluster key from the secret key", func(t *testing.T) {
		cfg := &Config{
			SecretKey:         testSecretKey,
			SessionSigningKey: "session-signing-key-0123456789",
		}

		err := cfg.SetSecretKey(nil)
		require.NoError(t, err)

		require.Equal(t, "404e93396b8ba2b7de9a69301912a1328dc660a4e188752d693e51cd2c57c82a", hex.EncodeToString(cfg.FrancisPSK()))

		// A different session signing key doesn't change the cluster key
		other := &Config{
			SecretKey:         testSecretKey,
			SessionSigningKey: "another-session-signing-key-0123",
		}
		err = other.SetSecretKey(nil)
		require.NoError(t, err)
		require.Equal(t, cfg.FrancisPSK(), other.FrancisPSK())
	})
}
