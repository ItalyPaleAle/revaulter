package protocolv2

import (
	"crypto/ecdh"
	"encoding/base64"
	"errors"
	"fmt"
)

// ECP256PublicJWK is the public JWK format used for ephemeral transport keys exchanged between CLI and browser.
type ECP256PublicJWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`

	// Explicitly reject private material and extra policy-sensitive fields in v2.
	D   string `json:"d,omitempty"`
	Kid string `json:"kid,omitempty"`
	Alg string `json:"alg,omitempty"`
	Use string `json:"use,omitempty"`
}

func (j *ECP256PublicJWK) ValidatePublic() error {
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
	if j.Kid != "" || j.Alg != "" || j.Use != "" {
		return errors.New("JWK must not include 'kid', 'alg', or 'use' fields")
	}
	_, err := decodeB64URL256(j.X)
	if err != nil {
		return fmt.Errorf("invalid JWK 'x': %w", err)
	}
	_, err = decodeB64URL256(j.Y)
	if err != nil {
		return fmt.Errorf("invalid JWK 'y': %w", err)
	}
	return nil
}

// ToECDHPublicKey converts the JWK into an ecdh public key.
func (j *ECP256PublicJWK) ToECDHPublicKey() (*ecdh.PublicKey, error) {
	err := j.ValidatePublic()
	if err != nil {
		return nil, err
	}

	x, _ := decodeB64URL256(j.X)
	y, _ := decodeB64URL256(j.Y)

	// SEC1 uncompressed point encoding: 0x04 || X || Y
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

// ECP256PublicJWKFromECDH converts an ecdh public key to a public JWK.
func ECP256PublicJWKFromECDH(pk *ecdh.PublicKey) (ECP256PublicJWK, error) {
	if pk == nil {
		return ECP256PublicJWK{}, errors.New("public key is nil")
	}

	raw := pk.Bytes()
	if len(raw) != 65 || raw[0] != 0x04 {
		return ECP256PublicJWK{}, fmt.Errorf("unexpected P-256 key encoding length: %d", len(raw))
	}

	return ECP256PublicJWK{
		Kty: "EC",
		Crv: "P-256",
		X:   base64.RawURLEncoding.EncodeToString(raw[1:33]),
		Y:   base64.RawURLEncoding.EncodeToString(raw[33:65]),
	}, nil
}

// Decodes a base64-url formatted string and enforces a length of 256 bits
func decodeB64URL256(s string) ([]byte, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(b) != 32 {
		return nil, fmt.Errorf("expected 32 bytes, got %d", len(b))
	}
	return b, nil
}
