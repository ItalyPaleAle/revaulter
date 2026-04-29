package protocolv2

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// ECP384PublicJWK is the public JWK format for the ECDSA leg of the user's hybrid anchor
// This is distinct from ECP256PublicJWK (which carries ephemeral ECDH transport keys): different curve, different usage, and the anchor key is long-lived instead of per-request
type ECP384PublicJWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`

	// Rejected if present; the anchor JWK must be a bare public key.
	D   string `json:"d,omitempty"`
	Kid string `json:"kid,omitempty"`
	Alg string `json:"alg,omitempty"`
	Use string `json:"use,omitempty"`
}

// p384CoordinateSize is the fixed byte length of a P-384 coordinate (384 bits)
const p384CoordinateSize = 48

func (j *ECP384PublicJWK) ValidatePublic() error {
	if j.Kty != "EC" {
		return fmt.Errorf("invalid JWK 'kty': %q", j.Kty)
	}
	if j.Crv != "P-384" {
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
	_, err := decodeB64URLFixed(j.X, p384CoordinateSize)
	if err != nil {
		return fmt.Errorf("invalid JWK 'x': %w", err)
	}
	_, err = decodeB64URLFixed(j.Y, p384CoordinateSize)
	if err != nil {
		return fmt.Errorf("invalid JWK 'y': %w", err)
	}
	return nil
}

// ToECDSAPublicKey converts the JWK into an ecdsa P-384 public key
func (j *ECP384PublicJWK) ToECDSAPublicKey() (*ecdsa.PublicKey, error) {
	err := j.ValidatePublic()
	if err != nil {
		return nil, err
	}

	x, _ := decodeB64URLFixed(j.X, p384CoordinateSize)
	y, _ := decodeB64URLFixed(j.Y, p384CoordinateSize)

	// Build the SEC1 uncompressed encoding (0x04 || X || Y) and let ecdsa.ParseUncompressedPublicKey perform the on-curve check
	uncompressed := make([]byte, 1+2*p384CoordinateSize)
	uncompressed[0] = 0x04
	copy(uncompressed[1:1+p384CoordinateSize], x)
	copy(uncompressed[1+p384CoordinateSize:], y)

	pk, err := ecdsa.ParseUncompressedPublicKey(elliptic.P384(), uncompressed)
	if err != nil {
		return nil, fmt.Errorf("invalid P-384 public point: %w", err)
	}
	return pk, nil
}

// ECP384PublicJWKFromECDSA converts an ECDSA P-384 public key to a JWK
func ECP384PublicJWKFromECDSA(pk *ecdsa.PublicKey) (ECP384PublicJWK, error) {
	if pk == nil || pk.Curve == nil {
		return ECP384PublicJWK{}, errors.New("public key is nil")
	}
	if pk.Curve != elliptic.P384() {
		return ECP384PublicJWK{}, errors.New("public key is not on P-384")
	}

	uncompressed, err := pk.Bytes()
	if err != nil {
		return ECP384PublicJWK{}, fmt.Errorf("encode public key: %w", err)
	}
	if len(uncompressed) != 1+2*p384CoordinateSize || uncompressed[0] != 0x04 {
		return ECP384PublicJWK{}, fmt.Errorf("unexpected uncompressed encoding length %d", len(uncompressed))
	}

	x := uncompressed[1:(1 + p384CoordinateSize)]
	y := uncompressed[(1 + p384CoordinateSize):]

	return ECP384PublicJWK{
		Kty: "EC",
		Crv: "P-384",
		X:   base64.RawURLEncoding.EncodeToString(x),
		Y:   base64.RawURLEncoding.EncodeToString(y),
	}, nil
}

// CanonicalBody encodes the ES384 anchor JWK as ordered `key=value` lines separated by `\n`, with no trailing newline
// The fields are emitted in alphabetical order (crv, kty, x, y) so client and server always produce identical bytes
func (j ECP384PublicJWK) CanonicalBody() string {
	var b strings.Builder
	b.Grow(len(j.Crv) + len(j.Kty) + len(j.X) + len(j.Y) + 16)
	b.WriteString("crv=")
	b.WriteString(j.Crv)
	b.WriteString("\nkty=")
	b.WriteString(j.Kty)
	b.WriteString("\nx=")
	b.WriteString(j.X)
	b.WriteString("\ny=")
	b.WriteString(j.Y)
	return b.String()
}

// ParseECP384PublicJWKCanonicalBody parses the string emitted by CanonicalBody back into a JWK
// The input must list every expected key in alphabetical order, exactly once, separated by `\n`, with no trailing newline
func ParseECP384PublicJWKCanonicalBody(body string) (ECP384PublicJWK, error) {
	lines := strings.Split(body, "\n")
	if len(lines) != 4 {
		return ECP384PublicJWK{}, fmt.Errorf("expected 4 lines, got %d", len(lines))
	}

	expected := [...]string{"crv", "kty", "x", "y"}
	values := [4]string{}
	for i, line := range lines {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return ECP384PublicJWK{}, fmt.Errorf("line %d missing '='", i)
		}
		if key != expected[i] {
			return ECP384PublicJWK{}, fmt.Errorf("line %d: expected key %q, got %q", i, expected[i], key)
		}
		values[i] = value
	}

	return ECP384PublicJWK{Crv: values[0], Kty: values[1], X: values[2], Y: values[3]}, nil
}

func decodeB64URLFixed(s string, size int) ([]byte, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(b) != size {
		return nil, fmt.Errorf("expected %d bytes, got %d", size, len(b))
	}
	return b, nil
}
