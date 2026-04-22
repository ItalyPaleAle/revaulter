package server

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// Wrapped anchor envelope schema: the decoded body is newline `key=value` in alphabetical order over exactly the required fields
// `v=1` is the only supported version; `nonce` is base64url of exactly 12 bytes; `ciphertext` is non-empty base64url
// Keep in sync with the browser emitter/parser in client/web/src/lib/crypto-anchor.ts
const (
	wrappedAnchorNonceSize = 12
	wrappedAnchorVersion   = "1"
)

var wrappedAnchorFields = [...]string{"ciphertext", "nonce", "v"}

// validateWrappedAnchorEnvelope performs structural validation on a wrapped-anchor blob
// It never decrypts the ciphertext; it only enforces that the envelope parses, has exactly the expected field set in the expected order, and that each field has the expected shape
func validateWrappedAnchorEnvelope(wrapped string) error {
	if wrapped == "" {
		return errors.New("wrappedAnchorKey is empty")
	}

	outer, err := base64.RawURLEncoding.DecodeString(wrapped)
	if err != nil {
		return fmt.Errorf("wrappedAnchorKey is not valid base64url: %w", err)
	}

	body := string(outer)
	lines := strings.Split(body, "\n")
	if len(lines) != len(wrappedAnchorFields) {
		return fmt.Errorf("expected %d lines, got %d", len(wrappedAnchorFields), len(lines))
	}

	seen := make(map[string]string, len(wrappedAnchorFields))
	for i, line := range lines {
		key, value, ok := strings.Cut(line, "=")
		if !ok || key == "" {
			return fmt.Errorf("line %d missing '='", i)
		}
		if key != wrappedAnchorFields[i] {
			return fmt.Errorf("line %d: expected key %q, got %q", i, wrappedAnchorFields[i], key)
		}
		_, dup := seen[key]
		if dup {
			return fmt.Errorf("duplicate key %q", key)
		}
		seen[key] = value
	}

	v := seen["v"]
	if v != wrappedAnchorVersion {
		return fmt.Errorf("unsupported version %q", v)
	}

	nonceB64 := seen["nonce"]
	if nonceB64 == "" {
		return errors.New("empty nonce")
	}

	ciphertextB64 := seen["ciphertext"]
	if ciphertextB64 == "" {
		return errors.New("empty ciphertext")
	}

	nonceBytes, err := base64.RawURLEncoding.DecodeString(nonceB64)
	if err != nil {
		return fmt.Errorf("nonce is not valid base64url: %w", err)
	}
	if len(nonceBytes) != wrappedAnchorNonceSize {
		return fmt.Errorf("nonce must be %d bytes, got %d", wrappedAnchorNonceSize, len(nonceBytes))
	}

	_, err = base64.RawURLEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return fmt.Errorf("ciphertext is not valid base64url: %w", err)
	}

	return nil
}
