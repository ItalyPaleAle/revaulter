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

// Cross-language fixtures for the key types whose material is too long to spell out as one hex constant
// Each is built as a fixed CBOR header, a body of repeated fill bytes standing in for the key material, and a fixed trailer
// These must stay identical to the fixtures in client/web/src/lib/cose-extract.test.ts
type coseFixture struct {
	name       string
	headerHex  string
	fill       byte
	bodyLen    int
	trailerHex string
	hash       string
}

// EdDSA is kty=OKP(1) alg=-8 crv=Ed25519(6) with a 32-byte x
// RS256 is kty=RSA(3) alg=-257 with a 256-byte modulus and the 65537 exponent
// ML-DSA-44 is kty=AKP(7) alg=-48 with the 1312-byte FIPS 204 public key, which is long enough that its CBOR length header takes two bytes
var coseFixtures = []coseFixture{
	{
		name:      "EdDSA",
		headerHex: "a4010103272006215820",
		fill:      0xcc,
		bodyLen:   32,
		hash:      "cofjKg9veiFnYvNi8MMJxabBwzBlQPpJg1vXJH6fyt4",
	},
	{
		name:       "RS256",
		headerHex:  "a401030339010020590100",
		fill:       0xab,
		bodyLen:    256,
		trailerHex: "2143010001",
		hash:       "jaLEoC-xsM5H9AgJeo8GTDcJxd5nBh5R4qw8gUkBEdg",
	},
	{
		name:      "ML-DSA-44",
		headerHex: "a3010703382f20590520",
		fill:      0xdd,
		bodyLen:   1312,
		hash:      "ag4GSXJUaUsb2zAkWkDsB_Uc9wNpi-zR90RqJnSJFDg",
	},
}

func (f coseFixture) bytes(t *testing.T) []byte {
	t.Helper()

	header, err := hex.DecodeString(f.headerHex)
	require.NoError(t, err)
	trailer, err := hex.DecodeString(f.trailerHex)
	require.NoError(t, err)

	out := make([]byte, 0, len(header)+f.bodyLen+len(trailer))
	out = append(out, header...)
	for range f.bodyLen {
		out = append(out, f.fill)
	}
	return append(out, trailer...)
}

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

func TestCredentialPublicKeyHash_NonECDSAFixturesMatchBrowser(t *testing.T) {
	for _, fixture := range coseFixtures {
		t.Run(fixture.name, func(t *testing.T) {
			got, err := CredentialPublicKeyHash(fixture.bytes(t))
			require.NoError(t, err)
			require.Equal(t, fixture.hash, got, "hash of raw COSE bytes must match the browser-computed hash for the same fixture")
		})
	}
}

func TestCredentialPublicKeyHashFromStoredCredJSON_NonECDSAFixtures(t *testing.T) {
	for _, fixture := range coseFixtures {
		t.Run(fixture.name, func(t *testing.T) {
			// encoding/json base64-encodes []byte with the standard encoding, which is the shape go-webauthn stores
			credJSON := `{"publicKey":"` + base64.StdEncoding.EncodeToString(fixture.bytes(t)) + `"}`
			got, err := CredentialPublicKeyHashFromStoredCredJSON(credJSON)
			require.NoError(t, err)
			require.Equal(t, fixture.hash, got)
		})
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
