package cmd

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/italypaleale/revaulter/pkg/protocolv2"
)

func TestDecryptV2ResponseEnvelope(t *testing.T) {
	// Generate CLI transport key pair (ECDH + ML-KEM)
	kp, err := newV2TransportKeyPair()
	require.NoError(t, err)

	// Simulate browser: ECDH key agreement
	browserEcdhPriv, err := ecdh.P256().GenerateKey(rand.Reader)
	require.NoError(t, err)
	ecdhShared, err := browserEcdhPriv.ECDH(kp.EcdhPrivate.PublicKey())
	require.NoError(t, err)

	// Simulate browser: ML-KEM encapsulation
	mlkemPubBytes, err := base64.RawURLEncoding.DecodeString(kp.MlkemPublic)
	require.NoError(t, err)
	mlkemPub, err := mlkem.NewEncapsulationKey768(mlkemPubBytes)
	require.NoError(t, err)
	mlkemShared, mlkemCT := mlkemPub.Encapsulate()

	// Combine shared secrets
	combined := make([]byte, 0, len(ecdhShared)+len(mlkemShared))
	combined = append(combined, ecdhShared...)
	combined = append(combined, mlkemShared...)
	key, err := deriveV2TransportKey(combined, "state-1")
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

	browserEcdhPubJWK, err := protocolv2.ECP256PublicJWKFromECDH(browserEcdhPriv.PublicKey())
	require.NoError(t, err)

	out, err := decryptV2ResponseEnvelope("state-1", kp, &protocolv2.ResponseEnvelope{
		TransportAlg:              "ecdh-p256+mlkem768+a256gcm",
		BrowserEphemeralPublicKey: browserEcdhPubJWK,
		MlkemCiphertext:           base64.RawURLEncoding.EncodeToString(mlkemCT),
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
