package cmd

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/italypaleale/revaulter/pkg/protocolv2"
)

func TestDecryptV2ResponseEnvelope(t *testing.T) {
	clientPriv, err := ecdh.P256().GenerateKey(rand.Reader)
	require.NoError(t, err)
	browserPriv, err := ecdh.P256().GenerateKey(rand.Reader)
	require.NoError(t, err)

	shared, err := browserPriv.ECDH(clientPriv.PublicKey())
	require.NoError(t, err)
	key, err := deriveV2TransportKey(shared, "state-1")
	require.NoError(t, err)

	block, err := aes.NewCipher(key)
	require.NoError(t, err)
	aead, err := cipher.NewGCM(block)
	require.NoError(t, err)

	nonce := make([]byte, aead.NonceSize())
	_, err = rand.Read(nonce)
	require.NoError(t, err)
	aad := buildTransportAAD("state-1", "encrypt", "aes-gcm-256")
	plain := []byte(`{"ok":true}`)
	ct := aead.Seal(nil, nonce, plain, aad)

	pubJWK, err := protocolv2.ECP256PublicJWKFromECDH(browserPriv.PublicKey())
	require.NoError(t, err)

	out, err := decryptV2ResponseEnvelope("state-1", clientPriv, &protocolv2.ResponseEnvelope{
		TransportAlg:              "ecdh-p256+a256gcm",
		BrowserEphemeralPublicKey: pubJWK,
		Nonce:                     base64.RawURLEncoding.EncodeToString(nonce),
		Ciphertext:                base64.RawURLEncoding.EncodeToString(ct),
	}, aad)
	require.NoError(t, err)
	require.Equal(t, string(plain), string(out))
}

func TestDeriveV2TransportKeyDeterministic(t *testing.T) {
	sum := sha256.Sum256([]byte("shared"))
	k1, err := deriveV2TransportKey(sum[:], "x")
	require.NoError(t, err)
	k2, err := deriveV2TransportKey(sum[:], "x")
	require.NoError(t, err)
	require.Equal(t, k1, k2)
	require.Len(t, k1, 32)
}

func TestBuildTransportAADMatchesBrowserOrdering(t *testing.T) {
	require.Equal(
		t,
		[]byte("algorithm=aes-gcm-256\noperation=encrypt\nstate=state-1\nv=1"),
		buildTransportAAD("state-1", "encrypt", "aes-gcm-256"),
	)
}
