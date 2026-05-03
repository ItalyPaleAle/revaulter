package config

import (
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"path/filepath"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwk"
)

// Config is the struct containing configuration
type Config struct {
	// Endpoint of the webhook, where notifications are sent to.
	// +required
	WebhookUrl string `env:"WEBHOOKURL" yaml:"webhookUrl"`

	// The format for the webhook.
	// Currently, these values are supported:
	//
	// - `plain`: sends a webhook with content type `text/plain`, where the request's body is the entire message
	// - `slack`: for usage with Slack or Slack-compatible endpoints
	// - `discord`: for usage with Discord (sends Slack-compatible messages)
	// +default "plain"
	WebhookFormat string `env:"WEBHOOKFORMAT" yaml:"webhookFormat"`

	// Value sent verbatim as the `Authorization` header on webhook requests
	// Revaulter does NOT add an authentication scheme prefix, so include one yourself if your downstream expects it
	// For example, set this to `Bearer abc123` for bearer-token auth, or `Basic dXNlcjpwYXNz` for HTTP Basic
	// Leave unset to omit the header entirely
	WebhookKey string `env:"WEBHOOKKEY" yaml:"webhookKey"`

	// The URL your application can be reached at. This is used in the links that are sent in webhook notifications.
	// This is optional, but recommended.
	// +default `https://localhost:<port>` if TLS is enabled, or `http://localhost:<port>` otherwise
	BaseUrl string `env:"BASEURL" yaml:"baseUrl"`

	// Port to bind to.
	// +default 8080
	Port int `env:"PORT" yaml:"port"`

	// Address/interface to bind to.
	// +default "0.0.0.0"
	Bind string `env:"BIND" yaml:"bind"`

	// Path where to load TLS certificates from. Within the folder, the files must be named `tls-cert.pem` and `tls-key.pem`. Revaulter watches for changes in this folder and automatically reloads the TLS certificates when they're updated.
	// If empty, certificates are loaded from the same folder where the loaded `config.yaml` is located.
	// +default the same folder as the `config.yaml` file
	TLSPath string `env:"TLSPATH" yaml:"tlsPath"`

	// Full, PEM-encoded TLS certificate. Using `tlsCertPEM` and `tlsKeyPEM` is an alternative method of passing TLS certificates than using `tlsPath`.
	TLSCertPEM string `env:"TLSCERTPEM" yaml:"tlsCertPEM"`

	// Full, PEM-encoded TLS key. Using `tlsCertPEM` and `tlsKeyPEM` is an alternative method of passing TLS certificates than using `tlsPath`.
	TLSKeyPEM string `env:"TLSKEYPEM" yaml:"tlsKeyPEM"`

	// Connection string for the database. The backend is inferred from the DSN (for example: `postgres://`, `postgresql://`, `sqlite://`).
	// If no scheme is present, the value is treated as a local SQLite file path.
	// +required
	DatabaseDSN string `env:"DATABASEDSN" yaml:"databaseDSN"`

	// Instance-wide secret to derive encryption keys.
	// It's recommended to generate with `openssl rand -base64 32`.
	//
	// IMPORTANT: rotating `secretKey` changes the PRF salt for every user effectively bricks every existing account. Treat this value as immutable for the lifetime of the instance; if you must rotate it, plan on every user re-registering from scratch.
	//
	// Note: this value is NOT used to encrypt anything server-side: all request payloads and responses are end-to-end encrypted in the browser, and the server only stores opaque envelopes.
	// +required
	SecretKey string `env:"SECRETKEY" yaml:"secretKey"`

	// Secret used to sign session tokens
	// It's recommended to generate with `openssl rand -base64 32`
	// If unset, Revaulter generates a random session signing key at startup, which invalidates existing sessions on restart
	SessionSigningKey string `env:"SESSIONSIGNINGKEY" yaml:"sessionSigningKey"`

	// WebAuthn RP ID for authentication
	// If empty, derived from `baseUrl`
	WebAuthnRPID string `env:"WEBAUTHNRPID" yaml:"webauthnRpId"`

	// WebAuthn RP display name for authentication.
	// +default "Revaulter"
	WebAuthnRPName string `env:"WEBAUTHNRPNAME" yaml:"webauthnRpName"`

	// Allowed origins for WebAuthn auth.
	// If empty, falls back to `baseUrl`
	WebAuthnOrigins []string `env:"WEBAUTHNORIGINS" yaml:"webauthnOrigins"`

	// Disable creation of new user accounts.
	// +default false
	DisableSignup bool `env:"DISABLESIGNUP" yaml:"disableSignup"`

	// Timeout for sessions before having to authenticate again, as a Go duration.
	// This cannot be more than 1 hour.
	// +default 5m
	SessionTimeout time.Duration `env:"SESSIONTIMEOUT" yaml:"sessionTimeout"`

	// Default timeout for request operations, as a Go duration.
	// This is the default value, and can be overridden in each request.
	// +default 5m
	RequestTimeout time.Duration `env:"REQUESTTIMEOUT" yaml:"requestTimeout"`

	// List of IPs or CIDRs of trusted proxies, which enables trusting the X-Forwarded-* headers
	// For example, `10.0.0.0/8`
	TrustedProxies []string `env:"TRUSTEDPROXIES" yaml:"trustedProxies"`

	// If true, calls to the healthcheck endpoint (`/healthz`) are included in the logs.
	// +default false
	LogHealthChecks bool `env:"LOGHEALTHCHECKS" yaml:"logHealthChecks"`

	// String with the name of a header to trust as ID of each request. The ID is included in logs and in responses as `X-Request-ID` header.
	// Common values can include:
	//
	// - `X-Request-ID`: a [de-facto standard](https://http.dev/x-request-id ) that's vendor agnostic
	// - `CF-Ray`: when the application is served by a [Cloudflare CDN](https://developers.cloudflare.com/fundamentals/get-started/reference/cloudflare-ray-id/)
	//
	// If this option is empty, or if it contains the name of a header that is not found in an incoming request, a random UUID is generated as request ID.
	TrustedRequestIdHeader string `env:"TRUSTEDREQUESTIDHEADER" yaml:"trustedRequestIdHeader"`

	// If true, forces all cookies to be set with the "secure" option, so they are only sent by clients on HTTPS requests.
	// When false (the default), cookies are set as "secure" only if the current request being served is using HTTPS.
	// When Revaulter is running behind a proxy that performs TLS termination, this option should normally be set to true.
	// +default false
	ForceSecureCookies bool `env:"FORCESECURECOOKIES" yaml:"forceSecureCookies"`

	// Controls log level and verbosity. Supported values: `debug`, `info` (default), `warn`, `error`.
	// +default "info"
	LogLevel string `env:"LOGLEVEL" yaml:"logLevel"`

	// If true, emits logs formatted as JSON, otherwise uses a text-based structured log format.
	// +default false if a TTY is attached (e.g. in development); true otherwise.
	LogAsJSON bool `env:"LOGASJSON" yaml:"logAsJson"`

	// Dev is meant for development only; it's undocumented
	Dev Dev `yaml:"-"`

	// internal keys
	internal internal `yaml:"-"`
}

// Dev includes options using during development only
type Dev struct {
	// If true, disables caching on the client
	DisableClientCache bool
	// If true, disables serving the client-side app
	DisableClientServing bool
}

// Internal properties
type internal struct {
	instanceID string

	// Path to the config file that was loaded
	configFileLoaded string

	// Session token signing key
	tokenSigningKey jwk.SymmetricKey

	// Base64-encoded PRF salt
	prfSalt string
}

// GetPRFSalt returns the PRF salt
func (c *Config) GetPRFSalt() string {
	return c.internal.prfSalt
}

// TokenSigningKey returns the derived signing key used for JWT sessions
func (c *Config) TokenSigningKey() jwk.SymmetricKey {
	return c.internal.tokenSigningKey
}

// GetLoadedConfigPath returns the path to the config file that was loaded
func (c *Config) GetLoadedConfigPath() string {
	return c.internal.configFileLoaded
}

// SetLoadedConfigPath sets the path to the config file that was loaded
func (c *Config) SetLoadedConfigPath(filePath string) {
	c.internal.configFileLoaded = filePath
}

// GetInstanceID returns the instance ID.
func (c *Config) GetInstanceID() string {
	return c.internal.instanceID
}

// GetTLSPath returns the path to look for TLS certificates in
func (c *Config) GetTLSPath() string {
	// If the TLSPath option is set, return that
	if c.TLSPath != "" {
		return c.TLSPath
	}

	// Start from the path where the config file is present
	file := c.GetLoadedConfigPath()
	if file != "" {
		return filepath.Dir(file)
	}

	// No path found
	return ""
}

// Validate the configuration and performs some sanitization
func (c *Config) Validate(logger *slog.Logger) error {
	// Check required variables
	if c.WebhookUrl == "" {
		return errors.New("config entry key 'webhookUrl' missing")
	}
	if c.DatabaseDSN == "" {
		return errors.New("config entry key 'databaseDSN' missing")
	}
	if c.SecretKey == "" {
		return errors.New("config entry key 'secretKey' missing")
	}

	// Validate the webhook URL
	parsedWebhook, err := url.Parse(c.WebhookUrl)
	if err != nil {
		return fmt.Errorf("config entry key 'webhookUrl' is invalid: %w", err)
	}
	if parsedWebhook.Scheme != "http" && parsedWebhook.Scheme != "https" {
		return fmt.Errorf("config entry key 'webhookUrl' has disallowed scheme %q: only http and https are permitted", parsedWebhook.Scheme)
	}

	// Ensure that the secret key is at least 20-character long (although ideally it's 32 or more, but enforcing some minimum standard)
	if len(c.SecretKey) < 20 {
		return errors.New("secret key is too short: must be at least 20 characters")
	}
	if c.SessionSigningKey != "" && len(c.SessionSigningKey) < 20 {
		return errors.New("session signing key is too short: must be at least 20 characters")
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

// SetSecretKey derives the instance-wide deterministic WebAuthn PRF salt from `secretKey` and the token signing key.
// The resulting salt is NOT used to encrypt any server-side data; it is purely the input-material anchor that every user's in-browser key derivation (static ECDH/ML-KEM decryption keys and per-operation AES-GCM keys) is bound to.
func (c *Config) SetSecretKey(logger *slog.Logger) (err error) {
	if c.SecretKey == "" {
		return errors.New("secret key value is empty")
	}
	sk := []byte(c.SecretKey)

	// Use HKDF to derive the 128-bit PRF salt
	prfSalt, err := hkdf.Key(sha256.New, sk, nil, "revaulter-prf-salt", 16)
	if err != nil {
		return fmt.Errorf("failed to derive PRF salt: %w", err)
	}
	c.internal.prfSalt = base64.RawURLEncoding.EncodeToString(prfSalt)

	// Use HKDF to derive the 256-bit token signing key from a session-specific secret
	tokenSigningKeyRaw, err := c.tokenSigningKeyRaw(logger)
	if err != nil {
		return err
	}

	// Import the token signing key as a jwk.Key
	c.internal.tokenSigningKey, err = jwk.Import[jwk.SymmetricKey](tokenSigningKeyRaw)
	if err != nil {
		return fmt.Errorf("failed to import token signing key as jwk.Key: %w", err)
	}

	// Calculate the key ID
	_ = c.internal.tokenSigningKey.Set(jwk.KeyIDKey, computeKeyId(tokenSigningKeyRaw))

	return nil
}

func (c *Config) tokenSigningKeyRaw(logger *slog.Logger) ([]byte, error) {
	if c.SessionSigningKey != "" {
		// If there's a sessionSigningKey, use HKDF to derive a 256-bit key
		tokenSigningKeyRaw, err := hkdf.Key(sha256.New, []byte(c.SessionSigningKey), nil, "revaulter-session-token", 32)
		if err != nil {
			return nil, fmt.Errorf("failed to derive token signing key: %w", err)
		}

		return tokenSigningKeyRaw, nil
	}

	if logger != nil {
		logger.Warn("config entry key 'sessionSigningKey' is empty: generated a random session signing key for this process")
	}

	// Generate a random key
	tokenSigningKeyRaw := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, tokenSigningKeyRaw)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random token signing key: %w", err)
	}

	return tokenSigningKeyRaw, nil
}

// Returns the key ID from a key
func computeKeyId(k []byte) string {
	h := sha256.Sum256(k)
	return base64.RawURLEncoding.EncodeToString(h[0:12])
}
