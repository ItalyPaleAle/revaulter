package config

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"

	"github.com/italypaleale/revaulter/pkg/utils"
)

// SetDBPayloadEncryptionKey parses and normalizes the v2 database payload encryption key.
// If the config value is empty, no key is stored and this is a no-op.
func (c *Config) SetDBPayloadEncryptionKey(logger *slog.Logger) error {
	if c.DBPayloadEncryptionKey == "" {
		c.internal.dbPayloadEncryptionKey = nil
		return nil
	}

	raw, err := parseFlexibleSecret(c.DBPayloadEncryptionKey)
	if err != nil {
		return fmt.Errorf("invalid 'dbPayloadEncryptionKey': %w", err)
	}
	if len(raw) == 0 {
		return errors.New("invalid 'dbPayloadEncryptionKey': empty value")
	}

	// Normalize to 32 bytes deterministically.
	// This allows operators to provide arbitrary secret lengths while we still use AES-256/HKDF-compatible key material.
	h := hmac.New(sha256.New, raw)
	_, _ = h.Write([]byte("revaulter-v2-db-payload-key"))
	c.internal.dbPayloadEncryptionKey = h.Sum(nil)

	if logger != nil {
		logger.Debug("Configured v2 database payload encryption key")
	}

	return nil
}

func parseFlexibleSecret(s string) ([]byte, error) {
	// Prefer hex when the string looks like hex and has even length.
	if len(s) >= 2 && len(s)%2 == 0 {
		if b, err := hex.DecodeString(s); err == nil {
			return b, nil
		}
	}

	b, err := utils.DecodeBase64String(s)
	if err != nil {
		return nil, errors.New("must be hex or base64/base64url")
	}
	return b, nil
}
