package config

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/rs/zerolog"
)

// Config is the struct containing configuration
type Config struct {
	AllowedIps             []string      `env:"ALLOWEDIPS" yaml:"allowedIps"`
	AzureClientId          string        `env:"AZURECLIENTID" yaml:"azureClientId"`
	AzureTenantId          string        `env:"AZURETENANTID" yaml:"azureTenantId"`
	BaseUrl                string        `env:"BASEURL" yaml:"baseUrl"`
	Bind                   string        `env:"BIND" yaml:"bind"`
	CookieEncryptionKey    string        `env:"COOKIEENCRYPTIONKEY" yaml:"cookieEncryptionKey"`
	EnableMetrics          bool          `env:"ENABLEMETRICS" yaml:"enableMetrics"`
	LogLevel               string        `env:"LOGLEVEL" yaml:"logLevel"`
	MetricsBind            string        `env:"METRICSBIND" yaml:"metricsBind"`
	MetricsPort            int           `env:"METRICSPORT" yaml:"metricsPort"`
	OmitHealthCheckLogs    bool          `env:"OMITHEALTHCHECKLOGS" yaml:"omitHealthCheckLogs"`
	Origins                []string      `env:"ORIGINS" yaml:"origins"`
	Port                   int           `env:"PORT" yaml:"port"`
	RequestTimeout         time.Duration `env:"REQUESTTIMEOUT" yaml:"requestTimeout"`
	RequestKey             string        `env:"REQUESTKEY" yaml:"requestKey"`
	SessionTimeout         time.Duration `env:"SESSIONTIMEOUT" yaml:"sessionTimeout"`
	TLSPath                string        `env:"TLSPATH" yaml:"tlsPath"`
	TLSCertPEM             string        `env:"TLSCERTPEM" yaml:"tlsCertPEM"`
	TLSKeyPEM              string        `env:"TLSKEYPEM" yaml:"tlsKeyPEM"`
	TokenSigningKey        string        `env:"TOKENSIGNINGKEY" yaml:"tokenSigningKey"`
	TrustedRequestIdHeader string        `env:"TRUSTEDREQUESTIDHEADER" yaml:"trustedRequestIdHeader"`
	WebhookFormat          string        `env:"WEBHOOKFORMAT" yaml:"webhookFormat"`
	WebhookKey             string        `env:"WEBHOOKKEY" yaml:"webhookKey"`
	WebhookUrl             string        `env:"WEBHOOKURL" yaml:"webhookUrl"`

	// Dev is meant for development only; it's undocumented
	Dev Dev `yaml:"-"`

	// internal keys
	internal internal `yaml:"-"`
}

// Dev includes options using during development only
type Dev struct {
	ClientProxyServer string
}

// Internal properties
type internal struct {
	configFileLoaded          string // Path to the config file that was loaded
	tokenSigningKeyParsed     []byte
	cookieEncryptionKeyParsed jwk.Key
	cookieSigningKeyParsed    jwk.Key
}

// GetTokenSigningKey returns the (parsed) token signing key
func (c Config) GetTokenSigningKey() []byte {
	return c.internal.tokenSigningKeyParsed
}

// GetCookieEncryptionKey returns the (parsed) cookie encryption key
func (c Config) GetCookieEncryptionKey() jwk.Key {
	return c.internal.cookieEncryptionKeyParsed
}

// GetCookieSigningKey returns the (parsed) cookie signing key
func (c Config) GetCookieSigningKey() jwk.Key {
	return c.internal.cookieSigningKeyParsed
}

// GetLoadedConfigPath returns the path to the config file that was loaded
func (c Config) GetLoadedConfigPath() string {
	return c.internal.configFileLoaded
}

// Validates the configuration and performs some sanitization
func (c *Config) Validate() error {
	// Check required variables
	if c.AzureClientId == "" {
		return errors.New("config entry key 'azureClientId' missing")
	}
	if c.AzureTenantId == "" {
		return errors.New("config entry key 'azureTenantId' missing")
	}
	if c.WebhookUrl == "" {
		return errors.New("config entry key 'webhookUrl' missing")
	}

	// Check for invalid values
	if c.SessionTimeout < time.Second || c.SessionTimeout > time.Hour {
		return errors.New("config entry key 'sessionTimeout' is invalid: must be between 1s and 1h")
	}
	if c.RequestTimeout < time.Second {
		return errors.New("config entry key 'requestTimeout' is invalid: must be greater than 1s")
	}

	return nil
}

// SetTokenSigningKey parses the token signing key.
// If it's empty, will generate a new one.
func (c *Config) SetTokenSigningKey(logger *zerolog.Logger) (err error) {
	b := []byte(c.TokenSigningKey)
	if len(b) == 0 {
		if logger != nil {
			logger.Debug().Msg("No 'tokenSigningKey' found in the configuration: a random one will be generated")
		}

		b := make([]byte, 18)
		_, err = io.ReadFull(rand.Reader, b)
		if err != nil {
			return fmt.Errorf("failed to generate random bytes: %w", err)
		}
	}

	// Compute a HMAC to ensure the key is 256-bit long
	h := hmac.New(crypto.SHA256.New, b)
	h.Write([]byte("revaulter-token-signing-jey"))
	c.internal.tokenSigningKeyParsed = h.Sum(nil)

	return nil
}

// SetCookieKeys sets the cookie encryption and signing keys.
func (c *Config) SetCookieKeys(logger *zerolog.Logger) (err error) {
	// If we have cookieEncryptionKey set, derive the keys from that
	// Otherwise, generate the keys randomly
	var (
		// Cookie Encryption Key, 128-bit (for AES-KW)
		cekRaw []byte
		// Cookie Signing Key, 256-bit (for HMAC-SHA256)
		cskRaw []byte
	)
	if c.CookieEncryptionKey != "" {
		h := hmac.New(crypto.SHA384.New, []byte(c.CookieEncryptionKey))
		h.Write([]byte("revaulter-cookie-keys"))
		sum := h.Sum(nil)
		cekRaw = sum[0:16]
		cskRaw = sum[16:]
	} else {
		if logger != nil {
			logger.Debug().Msg("No 'cookieEncryptionKey' found in the configuration: a random one will be generated")
		}

		cekRaw = make([]byte, 16)
		_, err = io.ReadFull(rand.Reader, cekRaw)
		if err != nil {
			return fmt.Errorf("failed to generate random cookieEncryptionKey: %w", err)
		}

		cskRaw = make([]byte, 32)
		_, err = io.ReadFull(rand.Reader, cekRaw)
		if err != nil {
			return fmt.Errorf("failed to generate random cookieSigningKey: %w", err)
		}
	}

	// Calculate the key ID
	kid := computeKeyId(cskRaw)

	// Import the keys as JWKs
	c.internal.cookieEncryptionKeyParsed, err = jwk.FromRaw(cekRaw)
	if err != nil {
		return fmt.Errorf("failed to import cookieEncryptionKey as jwk.Key: %w", err)
	}
	_ = c.internal.cookieEncryptionKeyParsed.Set("kid", kid)

	c.internal.cookieSigningKeyParsed, err = jwk.FromRaw(cskRaw)
	if err != nil {
		return fmt.Errorf("failed to import cookieSigningKey as jwk.Key: %w", err)
	}
	_ = c.internal.cookieSigningKeyParsed.Set("kid", kid)

	return nil
}

// Returns the key ID from a key
func computeKeyId(k []byte) string {
	h := sha256.Sum256(k)
	return base64.RawURLEncoding.EncodeToString(h[0:12])
}
