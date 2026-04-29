package protocolv2

import (
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

// Shared cross-language fixture: the exact same raw COSE bytes must hash to the same base64url digest on the server (this file) and in client/web/src/lib/cose-extract.test.ts
// If these constants change they must change in both places together
// cose_es256_hex is a hand-encoded ES256 (kty=EC2, alg=-7, crv=P-256) COSE key with x=32*0xAA and y=32*0xBB
const (
	fixtureCoseES256Hex = "a5010203262001215820aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa225820bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	fixtureExpectedHash = "YLaAiaKKf8P_gxCZdaWAwIiQLkrJAoCjl0QLZZb7sYk"
)

func TestCredentialPublicKeyHash_ES256FixtureMatchesBrowser(t *testing.T) {
	cose, err := hex.DecodeString(fixtureCoseES256Hex)
	require.NoError(t, err)
	got, err := CredentialPublicKeyHash(cose)
	require.NoError(t, err)
	require.Equal(t, fixtureExpectedHash, got, "hash of raw COSE bytes must match the browser-computed hash for the same fixture")
}

func TestCredentialPublicKeyHash_EdDSAAndRS256WorkWithoutAlgorithmSwitch(t *testing.T) {
	// The hash is algorithm-agnostic: any COSE key shape that the authenticator writes is accepted
	// Each input hashes to a distinct value so we exercise the "unknown algorithm" case without any per-algorithm code path
	cases := []string{
		// ES256 (copied from fixture)
		fixtureCoseES256Hex,
		// EdDSA / Ed25519: kty=OKP(1) alg=EdDSA(-8) crv=Ed25519(6) x=32 bytes of 0xCC
		"a401010327200620582056" + func() string {
			out := make([]byte, 0, 31)
			for range 31 {
				out = append(out, 0xcc)
			}
			return hex.EncodeToString(out)
		}(),
		// Synthetic RSA-shaped COSE: kty=3 alg=-257 with short bstr values; not real RSA material but well-formed CBOR
		"a40103033901002044010203042143010001",
	}
	seen := make(map[string]struct{}, len(cases))
	for i, hx := range cases {
		cose, err := hex.DecodeString(hx)
		require.NoError(t, err, "case %d decode", i)
		h, err := CredentialPublicKeyHash(cose)
		require.NoError(t, err, "case %d hash", i)
		_, dup := seen[h]
		require.False(t, dup, "case %d: hash collision across distinct COSE inputs", i)
		seen[h] = struct{}{}
	}
}

func TestCredentialPublicKeyHash_RejectsEmpty(t *testing.T) {
	_, err := CredentialPublicKeyHash(nil)
	require.Error(t, err)
	_, err = CredentialPublicKeyHash([]byte{})
	require.Error(t, err)
}

func TestCredentialPublicKeyHashFromStoredCredJSON(t *testing.T) {
	// extractStoredCredentialCOSE reads a go-webauthn Credential JSON with a `publicKey` base64-encoded field
	// We fabricate that shape directly with a known COSE payload and verify the hash matches the direct call
	cose, err := hex.DecodeString(fixtureCoseES256Hex)
	require.NoError(t, err)
	// base64 (std) of cose — `encoding/json` base64-encodes []byte using std encoding
	// But we can just use the helper to avoid hardcoding anything fragile
	credJSON := `{"publicKey":"` + base64.StdEncoding.EncodeToString(cose) + `"}`
	got, err := CredentialPublicKeyHashFromStoredCredJSON(credJSON)
	require.NoError(t, err)
	require.Equal(t, fixtureExpectedHash, got)
}

func TestCredentialPublicKeyHashFromStoredCredJSON_RejectsMissingFields(t *testing.T) {
	_, err := CredentialPublicKeyHashFromStoredCredJSON("")
	require.Error(t, err)
	_, err = CredentialPublicKeyHashFromStoredCredJSON(`{}`)
	require.Error(t, err)
	_, err = CredentialPublicKeyHashFromStoredCredJSON(`{"publicKey":""}`)
	require.Error(t, err)
	_, err = CredentialPublicKeyHashFromStoredCredJSON(`{`)
	require.Error(t, err)
}
