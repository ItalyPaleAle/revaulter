package main

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	nanoid "github.com/matoous/go-nanoid/v2"
	"github.com/rs/zerolog"
	"github.com/spf13/viper"

	"github.com/italypaleale/revaulter/pkg/config"
)

func loadConfig() error {
	// Defaults
	for k, v := range getDefaultConfig() {
		viper.SetDefault(k, v)
	}

	// Env
	viper.SetEnvPrefix("REVAULTER")
	viper.AutomaticEnv()

	// Config file
	viper.SetConfigName("config")
	viper.AddConfigPath(".")
	viper.AddConfigPath("$HOME/.revaulter")
	viper.AddConfigPath("/etc/revaulter")

	// Check if we have a specific config file to load
	confFile := os.Getenv("REVAULTER_CONFIG")
	if confFile != "" {
		viper.SetConfigFile(confFile)
	}

	// Read the config
	// Note: don't print any log that's not fatal-level before loading the desired log level
	err := viper.ReadInConfig()
	if err != nil {
		// Ignore errors if the config file doesn't exist
		var notfoundErr viper.ConfigFileNotFoundError
		if !errors.As(err, &notfoundErr) {
			return newLoadConfigError(err, "Error loading config file")
		}
	}

	// Process the configuration
	return processConfig()
}

// Gets the default config
func getDefaultConfig() map[string]any {
	return map[string]any{
		config.KeyLogLevel:       "info",
		config.KeyPort:           8080,
		config.KeyBind:           "0.0.0.0",
		config.KeySessionTimeout: 5 * time.Minute,
		config.KeyRequestTimeout: 5 * time.Minute,
	}
}

// Processes the configuration from viper
func processConfig() (err error) {
	// Log level
	err = setLogLevel()
	if err != nil {
		return err
	}

	// Check required variables
	err = validateConfig()
	if err != nil {
		return err
	}

	// Ensures the token signing key is present
	err = ensureTokenSigningKey()
	if err != nil {
		return err
	}

	// Set the cookie keys
	err = setCookieKeys()
	if err != nil {
		return err
	}

	return nil
}

// Validates the configuration and performs some sanitization
func validateConfig() error {
	// Check required variables
	if viper.GetString(config.KeyAzureClientId) == "" {
		return newLoadConfigError("Config entry key 'azureClientId' missing", "Invalid configuration")
	}
	if viper.GetString(config.KeyAzureTenantId) == "" {
		return newLoadConfigError("Config entry key 'azureTenantId' missing", "Invalid configuration")
	}
	if viper.GetString(config.KeyWebhookUrl) == "" {
		return newLoadConfigError("Config entry key 'webhookUrl' missing", "Invalid configuration")
	}

	// Check for invalid values
	if v := viper.GetDuration(config.KeySessionTimeout); v < time.Second || v > time.Hour {
		return newLoadConfigError("Config entry key 'sessionTimeout' is invalid: must be between 1s and 1h", "Invalid configuration")
	}
	if v := viper.GetDuration(config.KeyRequestTimeout); v < time.Second {
		return newLoadConfigError("Config entry key 'requestTimeout' is invalid: must be greater than 1s", "Invalid configuration")
	}

	// Lowercase the webhook format
	viper.Set(config.KeyWebhookFormat, strings.ToLower(viper.GetString(config.KeyWebhookFormat)))

	return nil
}

// Sets the log level based on the configuration
func setLogLevel() error {
	switch strings.ToLower(viper.GetString(config.KeyLogLevel)) {
	case "debug":
		appLogger.SetLogLevel(zerolog.DebugLevel)
	case "", "info": // Also default log level
		appLogger.SetLogLevel(zerolog.InfoLevel)
	case "warn":
		appLogger.SetLogLevel(zerolog.WarnLevel)
	case "error":
		appLogger.SetLogLevel(zerolog.ErrorLevel)
	default:
		return newLoadConfigError("Invalid value for 'logLevel'", "Invalid configuration")
	}
	return nil
}

// Ensures the token signing key is present
func ensureTokenSigningKey() (err error) {
	tokenSigningKey := viper.GetString(config.KeyTokenSigningKey)
	if tokenSigningKey == "" {
		appLogger.Raw().Debug().Msg("No 'tokenSigningKey' found in the configuration: a random one will be generated")

		tokenSigningKey, err = nanoid.New(21)
		if err != nil {
			return newLoadConfigError(err, "Failed to generate random tokenSigningKey")
		}
	}
	viper.Set(config.KeyInternalTokenSigningKey, tokenSigningKey)

	return nil
}

// Sets the cookie encryption and signing keys
func setCookieKeys() error {
	// If we have cookieEncryptionKey set, derive the keys from that
	// Otherwise, generate the keys randomly
	var (
		// Cookie Encryption Key, 128-bit (for AES-KW)
		cekRaw []byte
		// Cookie Signing Key, 256-bit (for HMAC-SHA256)
		cskRaw []byte
	)
	cekStr := viper.GetString(config.KeyCookieEncryptionKey)
	if cekStr != "" {
		h := hmac.New(crypto.SHA384.New, []byte(cekStr))
		h.Write([]byte("revaulter-cookie-keys"))
		sum := h.Sum(nil)
		cekRaw = sum[0:16]
		cskRaw = sum[16:]
	} else {
		appLogger.Raw().Debug().Msg("No 'cookieEncryptionKey' found in the configuration: a random one will be generated")

		cekRaw = make([]byte, 16)
		_, err := io.ReadFull(rand.Reader, cekRaw)
		if err != nil {
			return newLoadConfigError(err, "Failed to generate random cookieEncryptionKey")
		}

		cskRaw = make([]byte, 32)
		_, err = io.ReadFull(rand.Reader, cekRaw)
		if err != nil {
			return newLoadConfigError(err, "Failed to generate random cookieEncryptionKey")
		}
	}

	// Calculate the key ID
	kid := computeKeyId(cskRaw)

	// Import the keys as JWKs
	cek, err := jwk.FromRaw(cekRaw)
	if err != nil {
		return newLoadConfigError(err, "Failed to import cookieEncryptionKey as jwk.Key")
	}
	_ = cek.Set("kid", kid)
	viper.Set(config.KeyInternalCookieEncryptionKey, cek)

	csk, err := jwk.FromRaw(cskRaw)
	if err != nil {
		return newLoadConfigError(err, "Failed to import cookieSigningKey as jwk.Key")
	}
	_ = csk.Set("kid", kid)
	viper.Set(config.KeyInternalCookieSigningKey, csk)

	return nil
}

// Returns the key ID from a key
func computeKeyId(k []byte) string {
	h := sha256.Sum256(k)
	return base64.RawURLEncoding.EncodeToString(h[0:12])
}

// Error returned by loadConfig
type loadConfigError struct {
	err string
	msg string
}

// newLoadConfigError returns a new loadConfigError.
// The err argument can be a string or an error.
func newLoadConfigError(err any, msg string) *loadConfigError {
	return &loadConfigError{
		err: fmt.Sprintf("%v", err),
		msg: msg,
	}
}

// Error implements the error interface
func (e loadConfigError) Error() string {
	return e.err + ": " + e.msg
}

// LogFatal causes a fatal log
func (e loadConfigError) LogFatal() {
	appLogger.Raw().Fatal().
		Str("error", e.err).
		Msg(e.msg)
}
