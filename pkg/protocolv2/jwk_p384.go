package protocolv2

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
)

// ECP384PublicJWK is the public JWK format for the ECDSA leg of the user's hybrid anchor.
// This is distinct from ECP256PublicJWK (which carries ephemeral ECDH transport keys):
// different curve, different usage, and the anchor key is long-lived instead of per-request.
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

// p384CoordinateSize is the fixed byte length of a P-384 coordinate (384 bits).
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

// ToECDSAPublicKey converts the JWK into an ecdsa P-384 public key.
func (j *ECP384PublicJWK) ToECDSAPublicKey() (*ecdsa.PublicKey, error) {
	err := j.ValidatePublic()
	if err != nil {
		return nil, err
	}

	x, _ := decodeB64URLFixed(j.X, p384CoordinateSize)
	y, _ := decodeB64URLFixed(j.Y, p384CoordinateSize)

	curve := elliptic.P384()
	pk := &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(x),
		Y:     new(big.Int).SetBytes(y),
	}
	if !curve.IsOnCurve(pk.X, pk.Y) {
		return nil, errors.New("invalid P-384 public point: not on curve")
	}
	return pk, nil
}

// ECP384PublicJWKFromECDSA converts an ECDSA P-384 public key to a JWK.
func ECP384PublicJWKFromECDSA(pk *ecdsa.PublicKey) (ECP384PublicJWK, error) {
	if pk == nil || pk.Curve == nil {
		return ECP384PublicJWK{}, errors.New("public key is nil")
	}
	if pk.Curve != elliptic.P384() {
		return ECP384PublicJWK{}, errors.New("public key is not on P-384")
	}

	x := make([]byte, p384CoordinateSize)
	y := make([]byte, p384CoordinateSize)
	pk.X.FillBytes(x)
	pk.Y.FillBytes(y)

	return ECP384PublicJWK{
		Kty: "EC",
		Crv: "P-384",
		X:   base64.RawURLEncoding.EncodeToString(x),
		Y:   base64.RawURLEncoding.EncodeToString(y),
	}, nil
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
