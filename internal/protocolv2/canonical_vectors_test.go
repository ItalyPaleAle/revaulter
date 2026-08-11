// This file is an external test package because it imports the shared fixtures under testdata/, which themselves import protocolv2
package protocolv2_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/italypaleale/revaulter/internal/protocolv2"
	"github.com/italypaleale/revaulter/testdata"
)

// TestCanonicalVectorsMatchGoImplementation asserts every shared vector against the Go implementation
// The TypeScript suite asserts the same vectors against its own implementation, which is what keeps the two in agreement
func TestCanonicalVectorsMatchGoImplementation(t *testing.T) {
	v, err := testdata.LoadCanonicalVectors()
	require.NoError(t, err)

	t.Run("es384JwkCanonicalBody", func(t *testing.T) {
		require.NotEmpty(t, v.ES384JwkCanonicalBody)
		for _, tc := range v.ES384JwkCanonicalBody {
			t.Run(tc.Name, func(t *testing.T) {
				require.Equal(t, tc.CanonicalBody, tc.JWK.CanonicalBody())

				// The body must also parse back into the same JWK, so the format stays round-trippable
				parsed, err := protocolv2.ParseECP384PublicJWKCanonicalBody(tc.CanonicalBody)
				require.NoError(t, err)
				require.Equal(t, tc.JWK, parsed)
			})
		}
	})

	t.Run("attestation", func(t *testing.T) {
		require.NotEmpty(t, v.Attestation)
		for _, tc := range v.Attestation {
			t.Run(tc.Name, func(t *testing.T) {
				require.Equal(t, tc.CanonicalBody, tc.Payload.CanonicalBody())
				require.Equal(t, tc.Message, string(protocolv2.CanonicalAttestationMessage(&tc.Payload)))

				parsed, err := protocolv2.ParseAttestationPayload(tc.CanonicalBody)
				require.NoError(t, err)
				require.Equal(t, tc.Payload, parsed)
			})
		}
	})

	t.Run("pubkeyBundleV2", func(t *testing.T) {
		require.NotEmpty(t, v.PubkeyBundleV2)
		for _, tc := range v.PubkeyBundleV2 {
			t.Run(tc.Name, func(t *testing.T) {
				require.Equal(t, tc.CanonicalBody, tc.Payload.CanonicalBody())
				require.Equal(t, tc.Message, string(protocolv2.CanonicalPubkeyBundleMessageV2(&tc.Payload)))

				parsed, err := protocolv2.ParsePubkeyBundlePayloadV2(tc.CanonicalBody)
				require.NoError(t, err)
				require.Equal(t, tc.Payload, parsed)
			})
		}
	})

	t.Run("signingKeyPublication", func(t *testing.T) {
		require.NotEmpty(t, v.SigningKeyPublication)
		for _, tc := range v.SigningKeyPublication {
			t.Run(tc.Name, func(t *testing.T) {
				require.Equal(t, tc.CanonicalBody, tc.Payload.CanonicalBody())
				require.Equal(t, tc.Message, string(protocolv2.CanonicalSigningKeyPublicationMessage(&tc.Payload)))

				parsed, err := protocolv2.ParseSigningKeyPublicationPayload(tc.CanonicalBody)
				require.NoError(t, err)
				require.Equal(t, tc.Payload, parsed)
			})
		}
	})

	t.Run("jwkThumbprint", func(t *testing.T) {
		require.NotEmpty(t, v.JwkThumbprint)
		for _, tc := range v.JwkThumbprint {
			t.Run(tc.Name, func(t *testing.T) {
				var (
					got string
					err error
				)
				switch tc.JWK.Kty {
				case "EC":
					jwk := protocolv2.ECP256SigningJWK{Kty: tc.JWK.Kty, Crv: tc.JWK.Crv, X: tc.JWK.X, Y: tc.JWK.Y}
					got, err = jwk.Thumbprint()
				case "OKP":
					jwk := protocolv2.Ed25519SigningJWK{Kty: tc.JWK.Kty, Crv: tc.JWK.Crv, X: tc.JWK.X}
					got, err = jwk.Thumbprint()
				default:
					t.Fatalf("unsupported kty %q in vector", tc.JWK.Kty)
				}
				require.NoError(t, err)
				require.Equal(t, tc.Thumbprint, got)
			})
		}
	})
}

func TestCanonicalVectorsPrefixesAreStable(t *testing.T) {
	require.Equal(t, "revaulter/v2/cred-attest\n", protocolv2.CredAttestPrefix)
	require.Equal(t, "revaulter/v2/pubkey-bundle\n", protocolv2.PubkeyBundlePrefix)
	require.Equal(t, "revaulter/v2/signing-key-publication\n", protocolv2.SigningKeyPublicationPrefix)
}
