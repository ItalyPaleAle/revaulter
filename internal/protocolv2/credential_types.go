package protocolv2

import (
	"crypto/mldsa"
	"crypto/mlkem"
	"encoding/base64"
	"errors"
	"fmt"
	"unicode"
	"unicode/utf8"
)

// Credential types
// A passkey is a WebAuthn credential registered in the web app
// A device is a set of Secure Enclave keys registered by pairing a native app
const (
	CredentialTypePasskey = "passkey"
	CredentialTypeDevice  = "device"
)

// Fixed sizes of the keys, signatures and identifiers that make up a device credential
const (
	// P256PublicKeySize is the length of an uncompressed SEC 1 P-256 point (0x04 || X || Y), which is CryptoKit's x963Representation
	P256PublicKeySize = 65
	// P256SignatureSize is the length of a raw r||s P-256 signature, which is CryptoKit's rawRepresentation
	// ASN.1-DER encoded signatures are rejected
	P256SignatureSize = 64

	MLDSA65PublicKeySize = mldsa.MLDSA65PublicKeySize // 1952
	MLDSA65SignatureSize = mldsa.MLDSA65SignatureSize // 3309

	MLKEM768EncapsulationKeySize = mlkem.EncapsulationKeySize768 // 1184
	MLKEM768CiphertextSize       = mlkem.CiphertextSize768       // 1088

	// DeviceCredentialIDSize is the length of the random credential ID a device generates when it pairs
	DeviceCredentialIDSize = 16
)

// IsValidCredentialType reports whether t is a known credential type
func IsValidCredentialType(t string) bool {
	switch t {
	case CredentialTypePasskey, CredentialTypeDevice:
		return true
	default:
		return false
	}
}

// decodeBase64Field decodes a base64url (raw, no padding) value and checks its length
// A size of 0 accepts any non-empty value
// Decoding is strict, so each value has exactly one accepted encoding: hashes, MACs and signatures cover these strings, not the decoded bytes
func decodeBase64Field(field string, value string, size int) ([]byte, error) {
	if value == "" {
		return nil, fmt.Errorf("%s is empty", field)
	}

	b, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("%s is not valid base64url: %w", field, err)
	}

	if size > 0 && len(b) != size {
		return nil, fmt.Errorf("%s must be %d bytes, got %d", field, size, len(b))
	}

	return b, nil
}

// validateCanonicalText checks a free-form value that ends up in a canonical body
// Control characters are refused because a newline would let one field forge another field's line
func validateCanonicalText(field string, value string, maxLen int) error {
	if value == "" {
		return fmt.Errorf("%s is empty", field)
	}
	if len(value) > maxLen {
		return fmt.Errorf("%s must be at most %d bytes", field, maxLen)
	}
	if !utf8.ValidString(value) {
		return fmt.Errorf("%s is not valid UTF-8", field)
	}

	for _, r := range value {
		if unicode.IsControl(r) {
			return fmt.Errorf("%s contains a control character", field)
		}
	}

	return nil
}

// prefixedMessage returns prefix followed by body, as the bytes that get signed or MAC'd
func prefixedMessage(prefix string, body string) []byte {
	out := make([]byte, len(prefix)+len(body))
	copy(out[0:len(prefix)], prefix)
	copy(out[len(prefix):], body)
	return out
}

var errSignatureVerification = errors.New("signature verification failed")
