// This file is an external test package because it imports the shared fixtures under testdata/, which themselves import protocolv2
package protocolv2_test

import (
	"encoding/base64"
	"fmt"
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

	t.Run("devicePublicKeys", func(t *testing.T) {
		require.NotEmpty(t, v.DevicePublicKeys)
		for _, tc := range v.DevicePublicKeys {
			t.Run(tc.Name, func(t *testing.T) {
				require.Equal(t, tc.CanonicalBody, tc.Keys.CanonicalBody())
				require.Equal(t, tc.Hash, tc.Keys.Hash())
			})
		}
	})

	t.Run("attestationV2", func(t *testing.T) {
		require.NotEmpty(t, v.AttestationV2)
		for _, tc := range v.AttestationV2 {
			t.Run(tc.Name, func(t *testing.T) {
				require.Equal(t, tc.CanonicalBody, tc.Payload.CanonicalBody())
				require.Equal(t, tc.Message, string(protocolv2.CanonicalAttestationMessageV2(&tc.Payload)))

				parsed, err := protocolv2.ParseAttestationPayloadV2(tc.CanonicalBody)
				require.NoError(t, err)
				require.Equal(t, tc.Payload, parsed)

				version, err := protocolv2.AttestationPayloadVersion(tc.CanonicalBody)
				require.NoError(t, err)
				require.Equal(t, protocolv2.AttestationVersion2, version)
			})
		}

		// The v1 vectors must still be detected as v1
		for _, tc := range v.Attestation {
			version, err := protocolv2.AttestationPayloadVersion(tc.CanonicalBody)
			require.NoError(t, err)
			require.Equal(t, protocolv2.AttestationVersion1, version)
		}
	})

	t.Run("deviceLogin", func(t *testing.T) {
		require.NotEmpty(t, v.DeviceLogin)
		for _, tc := range v.DeviceLogin {
			t.Run(tc.Name, func(t *testing.T) {
				require.Equal(t, tc.CanonicalBody, tc.Payload.CanonicalBody())
				require.Equal(t, tc.Message, string(protocolv2.CanonicalDeviceLoginMessage(&tc.Payload)))
			})
		}
	})

	t.Run("deviceUnlockInfo", func(t *testing.T) {
		require.NotEmpty(t, v.DeviceUnlockInfo)
		for _, tc := range v.DeviceUnlockInfo {
			t.Run(tc.Name, func(t *testing.T) {
				ephPub := mustDecodeBase64URL(t, tc.EphPub)
				kemCt := mustDecodeBase64URL(t, tc.KemCt)
				require.Equal(t, tc.Info, protocolv2.DeviceUnlockInfo(tc.UserID, tc.CredentialID, ephPub, kemCt))
			})
		}
	})

	t.Run("pairingPayload", func(t *testing.T) {
		require.NotEmpty(t, v.PairingPayload)
		for _, tc := range v.PairingPayload {
			t.Run(tc.Name, func(t *testing.T) {
				require.Equal(t, tc.CanonicalBody, tc.Payload.CanonicalBody())
				require.Equal(t, tc.Text, tc.Payload.String())
				require.Equal(t, tc.Link, tc.Payload.Link())

				fromText, err := protocolv2.ParsePairingPayload(tc.Text)
				require.NoError(t, err)
				require.Equal(t, tc.Payload, fromText)

				fromLink, err := protocolv2.ParsePairingPayload(tc.Link)
				require.NoError(t, err)
				require.Equal(t, tc.Payload, fromLink)
			})
		}
	})

	t.Run("pairingMacKey", func(t *testing.T) {
		require.NotEmpty(t, v.PairingMACKey)
		for _, tc := range v.PairingMACKey {
			t.Run(tc.Name, func(t *testing.T) {
				require.Equal(t, tc.Info, fmt.Sprintf(protocolv2.PairingMACKeyInfoFmt, tc.SessionID))

				macKey, err := protocolv2.PairingMACKey(mustDecodeBase64URL(t, tc.Secret), tc.SessionID)
				require.NoError(t, err)
				require.Equal(t, tc.MACKey, base64.RawURLEncoding.EncodeToString(macKey))
			})
		}
	})

	t.Run("pairingTranscript", func(t *testing.T) {
		require.NotEmpty(t, v.PairingTranscript)
		for _, tc := range v.PairingTranscript {
			t.Run(tc.Name, func(t *testing.T) {
				require.Equal(t, tc.Message, string(protocolv2.CanonicalPairingHelloMessage(&tc.Transcript)))

				macKey := mustDecodeBase64URL(t, tc.MACKey)
				require.Equal(t, tc.MAC, base64.RawURLEncoding.EncodeToString(protocolv2.PairingHelloMAC(macKey, &tc.Transcript)))

				err := protocolv2.VerifyPairingHelloMAC(macKey, &tc.Transcript, mustDecodeBase64URL(t, tc.MAC))
				require.NoError(t, err)
			})
		}
	})

	t.Run("pairingNonce", func(t *testing.T) {
		require.NotEmpty(t, v.PairingNonce)
		for _, tc := range v.PairingNonce {
			t.Run(tc.Name, func(t *testing.T) {
				require.Equal(t, tc.Message, string(protocolv2.CanonicalPairingNonceMessage(&tc.Payload)))

				macKey := mustDecodeBase64URL(t, tc.MACKey)
				require.Equal(t, tc.MAC, base64.RawURLEncoding.EncodeToString(protocolv2.PairingNonceMAC(macKey, &tc.Payload)))
				require.Equal(t, tc.Code, protocolv2.PairingCode(macKey, &tc.Payload))

				err := protocolv2.VerifyPairingNonceMAC(macKey, &tc.Payload, mustDecodeBase64URL(t, tc.MAC))
				require.NoError(t, err)
			})
		}
	})
}

func TestCanonicalVectorsPrefixesAreStable(t *testing.T) {
	require.Equal(t, "revaulter/v2/cred-attest\n", protocolv2.CredAttestPrefix)
	require.Equal(t, "revaulter/v2/pubkey-bundle\n", protocolv2.PubkeyBundlePrefix)
	require.Equal(t, "revaulter/v2/signing-key-publication\n", protocolv2.SigningKeyPublicationPrefix)
	require.Equal(t, "revaulter/v2/device-public-keys\n", protocolv2.DevicePublicKeysPrefix)
	require.Equal(t, "revaulter/v2/device-login\n", protocolv2.DeviceLoginPrefix)
	require.Equal(t, "revaulter/v2/deviceUnlock\n", protocolv2.DeviceUnlockInfoPrefix)
	require.Equal(t, "revaulter/v2/pair/hello\n", protocolv2.PairingHelloPrefix)
	require.Equal(t, "revaulter/v2/pair/nonce\n", protocolv2.PairingNoncePrefix)
	require.Equal(t, "revaulter/v2/pair/code\n", protocolv2.PairingCodePrefix)
	require.Equal(t, "revaulter/v2/pair/mac\nsessionId=%s\nv=1", protocolv2.PairingMACKeyInfoFmt)
	require.Equal(t, "revaulter-pair:", protocolv2.PairingPayloadPrefix)
	require.Equal(t, "revaulter://pair/", protocolv2.PairingLinkPrefix)
}

func mustDecodeBase64URL(t *testing.T, s string) []byte {
	t.Helper()

	b, err := base64.RawURLEncoding.DecodeString(s)
	require.NoError(t, err)

	return b
}
