package protocolv2

import (
	"crypto/ecdh"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
)

// ECP256SigningJWK is the public JWK format for a published ES256 signing key
// Unlike ECP256PublicJWK (used for ephemeral transport keys) this permits the optional JWA metadata fields since published keys are long-lived and clients may legitimately set them
type ECP256SigningJWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`

	Alg string `json:"alg,omitempty"`
	Use string `json:"use,omitempty"`
	Kid string `json:"kid,omitempty"`

	// D must never be set on a published key — it is the private scalar
	D string `json:"d,omitempty"`
}

// ValidateSigningKey enforces the structural and algorithmic constraints for a published ES256 signing JWK
func (j *ECP256SigningJWK) ValidateSigningKey() error {
	if j.Kty != "EC" {
		return fmt.Errorf("invalid JWK 'kty': %q", j.Kty)
	}
	if j.Crv != "P-256" {
		return fmt.Errorf("invalid JWK 'crv': %q", j.Crv)
	}
	if j.X == "" || j.Y == "" {
		return errors.New("JWK is missing 'x' or 'y'")
	}
	if j.D != "" {
		return errors.New("JWK must not include private member 'd'")
	}
	if j.Alg != "" && j.Alg != SigningAlgES256 {
		return fmt.Errorf("invalid JWK 'alg': %q", j.Alg)
	}
	if j.Use != "" && j.Use != "sig" {
		return fmt.Errorf("invalid JWK 'use': %q", j.Use)
	}

	return nil
}

// ToECDHPublicKey converts the signing JWK into a *ecdh.PublicKey (P-256)
// This also serves as the canonical on-curve check
func (j *ECP256SigningJWK) ToECDHPublicKey() (*ecdh.PublicKey, error) {
	x, err := decodeB64URL256(j.X)
	if err != nil {
		return nil, fmt.Errorf("invalid JWK 'x': %w", err)
	}

	y, err := decodeB64URL256(j.Y)
	if err != nil {
		return nil, fmt.Errorf("invalid JWK 'y': %w", err)
	}

	buf := make([]byte, 1+32+32)
	buf[0] = 0x04
	copy(buf[1:33], x)
	copy(buf[33:], y)
	pk, err := ecdh.P256().NewPublicKey(buf)
	if err != nil {
		return nil, fmt.Errorf("invalid P-256 public point: %w", err)
	}

	return pk, nil
}

// Thumbprint returns the RFC 7638 JWK thumbprint of the signing key as a base64url-encoded SHA-256 digest
// The thumbprint is computed only over the required members (crv, kty, x, y) in lexicographic order
func (j *ECP256SigningJWK) Thumbprint() (string, error) {
	err := j.ValidateSigningKey()
	if err != nil {
		return "", err
	}

	// Serialize the required members in lexicographic order via encoding/json so the string escaping is JSON-spec compliant
	canonical, err := json.Marshal(struct {
		Crv string `json:"crv"`
		Kty string `json:"kty"`
		X   string `json:"x"`
		Y   string `json:"y"`
	}{Crv: j.Crv, Kty: j.Kty, X: j.X, Y: j.Y})
	if err != nil {
		return "", fmt.Errorf("failed to serialize JWK for thumbprint: %w", err)
	}

	h := sha256.Sum256(canonical)
	return base64.RawURLEncoding.EncodeToString(h[:]), nil
}

// ECP256SigningJWKFromECDH converts a *ecdh.PublicKey on P-256 to a JWK
func ECP256SigningJWKFromECDH(pk *ecdh.PublicKey) (ECP256SigningJWK, error) {
	if pk == nil {
		return ECP256SigningJWK{}, errors.New("public key is nil")
	}
	raw := pk.Bytes()
	if len(raw) != 65 || raw[0] != 0x04 {
		return ECP256SigningJWK{}, fmt.Errorf("unexpected P-256 key encoding length: %d", len(raw))
	}
	return ECP256SigningJWK{
		Kty: "EC",
		Crv: "P-256",
		X:   base64.RawURLEncoding.EncodeToString(raw[1:33]),
		Y:   base64.RawURLEncoding.EncodeToString(raw[33:65]),
	}, nil
}

// ParseECP256SigningJWK parses and validates a JWK from JSON bytes
func ParseECP256SigningJWK(raw []byte) (ECP256SigningJWK, error) {
	var j ECP256SigningJWK
	err := json.Unmarshal(raw, &j)
	if err != nil {
		return ECP256SigningJWK{}, fmt.Errorf("invalid JWK JSON: %w", err)
	}

	err = j.ValidateSigningKey()
	if err != nil {
		return ECP256SigningJWK{}, err
	}

	return j, nil
}

// ParseECP256SigningPEM parses a PEM-encoded PKIX public key and returns the raw uncompressed SEC1 encoding (0x04 || X || Y) if the key is on P-256
// This encoding is what ecdh.P256().NewPublicKey consumes and is equivalent to the underlying bytes of an ecdh.PublicKey
func ParseECP256SigningPEM(pemBytes []byte) ([]byte, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("invalid PEM: no block found")
	}

	// We only support keys in PKIX format, which are in PEM blocks of type "PUBLIC KEY"
	if block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("invalid PEM block type: %q", block.Type)
	}

	pk, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("invalid PKIX public key: %w", err)
	}

	// Accept only ECDSA/ECDH P-256 keys
	// Convert via ecdh if possible so we avoid reading deprecated ecdsa.PublicKey fields
	ek, ok := pk.(interface {
		ECDH() (*ecdh.PublicKey, error)
	})
	if ok {
		edh, convErr := ek.ECDH()
		if convErr != nil {
			return nil, fmt.Errorf("public key is not on P-256: %w", convErr)
		}
		if edh.Curve() != ecdh.P256() {
			return nil, errors.New("public key must be on P-256")
		}

		return edh.Bytes(), nil
	}

	return nil, errors.New("PEM public key is not an ECDSA key")
}
