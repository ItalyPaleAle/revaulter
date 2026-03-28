package config

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"log/slog"
)

// SetSecretKey parses and normalizes the secret key.
func (c *Config) SetSecretKey(logger *slog.Logger) error {
	if c.SecretKey == "" {
		return errors.New("secret key value is empty")
	}

	// Derive a 256-bit key using HMAC-SHA256 from the user-provided value
	h := hmac.New(sha256.New, []byte(c.SecretKey))
	_, _ = h.Write([]byte("revaulter-v2-secret-key"))
	c.internal.secretKey = h.Sum(nil)

	if logger != nil {
		logger.Debug("Configured database payload encryption key")
	}

	return nil
}
