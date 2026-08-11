package protocolv2

import (
	"crypto/ecdh"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestECP256PublicJWKRoundTrip(t *testing.T) {
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	require.NoError(t, err)

	jwk, err := ECP256PublicJWKFromECDH(priv.PublicKey())
	require.NoError(t, err)
	require.Equal(t, "EC", jwk.Kty)
	require.Equal(t, "P-256", jwk.Crv)

	pub, err := jwk.ToECDHPublicKey()
	require.NoError(t, err)
	require.Equal(t, priv.PublicKey().Bytes(), pub.Bytes())
}

func TestECP256PublicJWKValidateRejectsInvalid(t *testing.T) {
	tests := []struct {
		name string
		jwk  ECP256PublicJWK
	}{
		{
			name: "private-d-present",
			jwk:  ECP256PublicJWK{Kty: "EC", Crv: "P-256", X: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", Y: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", D: "secret"},
		},
		{
			name: "wrong-curve",
			jwk:  ECP256PublicJWK{Kty: "EC", Crv: "P-384", X: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", Y: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
		},
		{
			name: "extra-kid",
			jwk:  ECP256PublicJWK{Kty: "EC", Crv: "P-256", X: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", Y: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", Kid: "x"},
		},
		{
			name: "missing-y",
			jwk:  ECP256PublicJWK{Kty: "EC", Crv: "P-256", X: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Error(t, tt.jwk.ValidatePublic())
		})
	}
}
