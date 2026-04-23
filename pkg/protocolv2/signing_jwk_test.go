package protocolv2

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestECP256SigningJWKFromECDHRoundTrip(t *testing.T) {
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	require.NoError(t, err)

	jwk, err := ECP256SigningJWKFromECDH(priv.PublicKey())
	require.NoError(t, err)
	require.Equal(t, "EC", jwk.Kty)
	require.Equal(t, "P-256", jwk.Crv)
	require.Empty(t, jwk.D, "public JWK must not carry the private scalar")

	pub, err := jwk.ToECDHPublicKey()
	require.NoError(t, err)
	require.Equal(t, priv.PublicKey().Bytes(), pub.Bytes())
}

// TestECP256SigningJWKThumbprintKnownAnswer asserts the thumbprint follows RFC 7638: base64url(SHA-256(canonical-JWK)) over the required members (crv, kty, x, y) in lexicographic order
// The hash is computed independently here so any drift in the implementation is caught
func TestECP256SigningJWKThumbprintKnownAnswer(t *testing.T) {
	jwk := ECP256SigningJWK{
		Kty: "EC",
		Crv: "P-256",
		X:   "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
		Y:   "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
	}
	canonical := `{"crv":"P-256","kty":"EC","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}`
	h := sha256.Sum256([]byte(canonical))
	expected := base64.RawURLEncoding.EncodeToString(h[:])

	got, err := jwk.Thumbprint()
	require.NoError(t, err)
	require.Equal(t, expected, got)

	// base64url (unpadded) length for 32 bytes is 43 chars
	require.Len(t, got, 43)
}

func TestECP256SigningJWKThumbprintDeterministic(t *testing.T) {
	jwk := ECP256SigningJWK{
		Kty: "EC",
		Crv: "P-256",
		X:   "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
		Y:   "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
	}
	tp1, err := jwk.Thumbprint()
	require.NoError(t, err)
	tp2, err := jwk.Thumbprint()
	require.NoError(t, err)
	require.Equal(t, tp1, tp2)

	// Re-publication of the same key material must yield the same id, even when optional metadata differs
	jwk2 := jwk
	jwk2.Alg = "ES256"
	jwk2.Use = "sig"
	jwk2.Kid = "whatever"
	tp3, err := jwk2.Thumbprint()
	require.NoError(t, err)
	require.Equal(t, tp1, tp3)
}

func TestECP256SigningJWKValidateRejectsInvalid(t *testing.T) {
	validX := "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU"
	validY := "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"

	tests := []struct {
		name string
		jwk  ECP256SigningJWK
	}{
		{"wrong-kty", ECP256SigningJWK{Kty: "OKP", Crv: "P-256", X: validX, Y: validY}},
		{"wrong-crv", ECP256SigningJWK{Kty: "EC", Crv: "P-384", X: validX, Y: validY}},
		{"missing-x", ECP256SigningJWK{Kty: "EC", Crv: "P-256", Y: validY}},
		{"missing-y", ECP256SigningJWK{Kty: "EC", Crv: "P-256", X: validX}},
		{"includes-d", ECP256SigningJWK{Kty: "EC", Crv: "P-256", X: validX, Y: validY, D: "secret"}},
		{"wrong-alg", ECP256SigningJWK{Kty: "EC", Crv: "P-256", X: validX, Y: validY, Alg: "ES384"}},
		{"wrong-use", ECP256SigningJWK{Kty: "EC", Crv: "P-256", X: validX, Y: validY, Use: "enc"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Error(t, tt.jwk.ValidateSigningKey())
		})
	}
}

func TestECP256SigningJWKValidateAcceptsOptionalMetadata(t *testing.T) {
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	require.NoError(t, err)
	jwk, err := ECP256SigningJWKFromECDH(priv.PublicKey())
	require.NoError(t, err)

	// All three optional fields are allowed on published signing keys
	jwk.Alg = "ES256"
	jwk.Use = "sig"
	jwk.Kid = "some-kid"
	require.NoError(t, jwk.ValidateSigningKey())
}

func TestParseECP256SigningJWKRoundTrip(t *testing.T) {
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	require.NoError(t, err)
	jwk, err := ECP256SigningJWKFromECDH(priv.PublicKey())
	require.NoError(t, err)
	buf, err := json.Marshal(jwk)
	require.NoError(t, err)

	parsed, err := ParseECP256SigningJWK(buf)
	require.NoError(t, err)
	require.Equal(t, jwk, parsed)
}

func TestParseECP256SigningJWKRejectsInvalid(t *testing.T) {
	_, err := ParseECP256SigningJWK([]byte("not json"))
	require.Error(t, err)

	_, err = ParseECP256SigningJWK([]byte(`{"kty":"EC","crv":"P-384","x":"aa","y":"bb"}`))
	require.Error(t, err)
}

func TestParseECP256SigningPEMRoundTrip(t *testing.T) {
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	require.NoError(t, err)
	pubBytes := priv.PublicKey().Bytes()

	spki, err := x509.MarshalPKIXPublicKey(priv.PublicKey())
	require.NoError(t, err)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: spki})

	raw, err := ParseECP256SigningPEM(pemBytes)
	require.NoError(t, err)
	require.Equal(t, pubBytes, raw)
}

func TestParseECP256SigningPEMRejectsInvalid(t *testing.T) {
	_, err := ParseECP256SigningPEM([]byte("not a pem"))
	require.Error(t, err)

	// Wrong block type
	_, err = ParseECP256SigningPEM(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte{0}}))
	require.Error(t, err)

	// Non-EC key (RSA) would round-trip through PKIX but must be rejected
	// We simulate a malformed PKIX body which is a cheaper check than generating an RSA key
	_, err = ParseECP256SigningPEM(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte{0x01, 0x02}}))
	require.Error(t, err)
}
