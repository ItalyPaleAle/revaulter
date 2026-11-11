package protocolv2

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func b64(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// webEnvelope encodes JSON the way the web client's wrapPrimaryKey does
func webEnvelope(json string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(json))
}

func testDeviceEnvelope(t *testing.T) *WrappedPrimaryKeyEnvelope {
	t.Helper()

	eph, err := ecdh.P256().GenerateKey(rand.Reader)
	require.NoError(t, err)

	return &WrappedPrimaryKeyEnvelope{
		V:                WrappedPrimaryKeyVersion,
		Kind:             WrappedKeyKindDevice,
		PasswordRequired: true,
		Argon2id: &Argon2idParams{
			M:    128 << 10,
			T:    4,
			P:    1,
			Salt: b64(make([]byte, argon2idSaltSize)),
		},
		EphPub:     b64(eph.PublicKey().Bytes()),
		KemCt:      b64(make([]byte, MLKEM768CiphertextSize)),
		Nonce:      b64(make([]byte, wrappedPrimaryKeyNonceSize)),
		Ciphertext: b64(make([]byte, wrappedPrimaryKeyCiphertextSize)),
	}
}

func TestParseWrappedPrimaryKeyEnvelopeWebFormat(t *testing.T) {
	nonce := b64(make([]byte, 12))
	ciphertext := b64(make([]byte, 48))
	salt := b64(make([]byte, 16))

	t.Run("passkey without a password", func(t *testing.T) {
		env, err := ParseWrappedPrimaryKeyEnvelope(webEnvelope(`{"v":1,"passwordRequired":false,"nonce":"` + nonce + `","ciphertext":"` + ciphertext + `"}`))
		require.NoError(t, err)
		require.False(t, env.IsDevice())
		require.False(t, env.PasswordRequired)
		require.Nil(t, env.Argon2id)
	})

	t.Run("passkey with a password at the production cost", func(t *testing.T) {
		env, err := ParseWrappedPrimaryKeyEnvelope(webEnvelope(`{"v":1,"passwordRequired":true,"nonce":"` + nonce + `","ciphertext":"` + ciphertext + `","argon2id":{"m":131072,"t":4,"p":1,"salt":"` + salt + `"}}`))
		require.NoError(t, err)
		require.True(t, env.PasswordRequired)
		require.Equal(t, Argon2idParams{M: 131072, T: 4, P: 1, Salt: salt}, *env.Argon2id)
	})

	t.Run("passkey with a password at the end-to-end test cost", func(t *testing.T) {
		_, err := ParseWrappedPrimaryKeyEnvelope(webEnvelope(`{"v":1,"passwordRequired":true,"nonce":"` + nonce + `","ciphertext":"` + ciphertext + `","argon2id":{"m":8,"t":1,"p":1,"salt":"` + salt + `"}}`))
		require.NoError(t, err)
	})
}

func TestWrappedPrimaryKeyEnvelopeDeviceRoundTrip(t *testing.T) {
	env := testDeviceEnvelope(t)

	encoded, err := env.Encode()
	require.NoError(t, err)

	parsed, err := ParseWrappedPrimaryKeyEnvelope(encoded)
	require.NoError(t, err)
	require.Equal(t, env, parsed)
	require.True(t, parsed.IsDevice())
}

func TestWrappedPrimaryKeyEnvelopeValidate(t *testing.T) {
	notOnCurve := make([]byte, P256PublicKeySize)
	notOnCurve[0] = 0x04

	tests := []struct {
		name   string
		mutate func(e *WrappedPrimaryKeyEnvelope)
		errMsg string
	}{
		{"unknown version", func(e *WrappedPrimaryKeyEnvelope) { e.V = 2 }, "unsupported wrapped primary key version"},
		{"unknown kind", func(e *WrappedPrimaryKeyEnvelope) { e.Kind = "passkey" }, "unsupported wrapped primary key kind"},
		{"passkey envelope with device fields", func(e *WrappedPrimaryKeyEnvelope) { e.Kind = "" }, "only allowed in device envelopes"},
		{"device envelope without ephPub", func(e *WrappedPrimaryKeyEnvelope) { e.EphPub = "" }, "ephPub is empty"},
		{"ephPub not on the curve", func(e *WrappedPrimaryKeyEnvelope) { e.EphPub = b64(notOnCurve) }, "ephPub is not a valid P-256 public key"},
		{"kemCt wrong size", func(e *WrappedPrimaryKeyEnvelope) { e.KemCt = b64(make([]byte, 1568)) }, "kemCt must be 1088 bytes"},
		{"password flag without parameters", func(e *WrappedPrimaryKeyEnvelope) { e.Argon2id = nil }, "argon2id parameters must be present"},
		{"parameters without password flag", func(e *WrappedPrimaryKeyEnvelope) { e.PasswordRequired = false }, "argon2id parameters must be present"},
		{"zero parallelism", func(e *WrappedPrimaryKeyEnvelope) { e.Argon2id.P = 0 }, "parallelism"},
		{"too much parallelism", func(e *WrappedPrimaryKeyEnvelope) { e.Argon2id.P = MaxArgon2idParallelism + 1 }, "parallelism"},
		{"zero iterations", func(e *WrappedPrimaryKeyEnvelope) { e.Argon2id.T = 0 }, "iterations"},
		{"too many iterations", func(e *WrappedPrimaryKeyEnvelope) { e.Argon2id.T = MaxArgon2idIterations + 1 }, "iterations"},
		{"memory below 8 KiB per lane", func(e *WrappedPrimaryKeyEnvelope) { e.Argon2id.P = 2; e.Argon2id.M = 15 }, "memory"},
		{"memory above the cap", func(e *WrappedPrimaryKeyEnvelope) { e.Argon2id.M = MaxArgon2idMemoryKiB + 1 }, "memory"},
		{"short salt", func(e *WrappedPrimaryKeyEnvelope) { e.Argon2id.Salt = b64(make([]byte, 8)) }, "salt must be 16 bytes"},
		{"wrong nonce size", func(e *WrappedPrimaryKeyEnvelope) { e.Nonce = b64(make([]byte, 16)) }, "nonce must be 12 bytes"},
		{"wrong ciphertext size", func(e *WrappedPrimaryKeyEnvelope) { e.Ciphertext = b64(make([]byte, 32)) }, "ciphertext must be 48 bytes"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env := testDeviceEnvelope(t)
			tc.mutate(env)

			err := env.Validate()
			require.Error(t, err)
			require.ErrorContains(t, err, tc.errMsg)

			// Encode refuses the same envelope
			_, err = env.Encode()
			require.Error(t, err)
		})
	}
}

func TestParseWrappedPrimaryKeyEnvelopeRejectsMalformedInput(t *testing.T) {
	tests := []struct {
		name    string
		wrapped string
		errMsg  string
	}{
		{"empty", "", "is empty"},
		{"too long", strings.Repeat("A", MaxWrappedPrimaryKeyLength+1), "at most"},
		{"not base64url", "not base64!", "not valid base64url"},
		{"not JSON", webEnvelope("v=1"), "not a valid envelope"},
		{"wrong JSON type", webEnvelope(`{"v":"1"}`), "not a valid envelope"},
		{"negative memory", webEnvelope(`{"v":1,"passwordRequired":true,"argon2id":{"m":-1,"t":1,"p":1,"salt":"AAAAAAAAAAAAAAAAAAAAAA"}}`), "not a valid envelope"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseWrappedPrimaryKeyEnvelope(tc.wrapped)
			require.Error(t, err)
			require.ErrorContains(t, err, tc.errMsg)
		})
	}
}

func FuzzParseWrappedPrimaryKeyEnvelope(f *testing.F) {
	nonce := b64(make([]byte, 12))
	ciphertext := b64(make([]byte, 48))
	f.Add(webEnvelope(`{"v":1,"passwordRequired":false,"nonce":"` + nonce + `","ciphertext":"` + ciphertext + `"}`))
	f.Add(webEnvelope(`{"v":1,"kind":"device","passwordRequired":false,"ephPub":"","kemCt":"","nonce":"` + nonce + `","ciphertext":"` + ciphertext + `"}`))
	f.Add("")

	f.Fuzz(func(t *testing.T, wrapped string) {
		env, err := ParseWrappedPrimaryKeyEnvelope(wrapped)
		if err != nil {
			return
		}

		// Anything that parses must re-encode and parse back to the same envelope
		encoded, err := env.Encode()
		require.NoError(t, err)

		again, err := ParseWrappedPrimaryKeyEnvelope(encoded)
		require.NoError(t, err)
		require.Equal(t, env, again)
	})
}
