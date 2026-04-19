package protocolv2

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	"github.com/stretchr/testify/require"
)

// Helpers.

func testAttestationPayload() AttestationPayload {
	return AttestationPayload{
		UserID:              "user-123",
		CredentialID:        "cred-abc",
		CredentialPublicKey: base64.RawURLEncoding.EncodeToString([]byte("cred-public-key-bytes")),
		WrappedKeyEpoch:     1,
		CreatedAt:           1720000000,
	}
}

func testBundlePayload() PubkeyBundlePayload {
	return PubkeyBundlePayload{
		UserID:                 "user-123",
		RequestEncEcdhPubkey:   `{"kty":"EC","crv":"P-256","x":"xxx","y":"yyy"}`,
		RequestEncMlkemPubkey:  base64.RawURLEncoding.EncodeToString([]byte("mlkem-pub-bytes")),
		AnchorEs384PublicKey:   `{"kty":"EC","crv":"P-384","x":"aaa","y":"bbb"}`,
		AnchorMldsa87PublicKey: base64.RawURLEncoding.EncodeToString([]byte("mldsa87-pub-bytes")),
		WrappedKeyEpoch:        1,
	}
}

func signES384Raw(t *testing.T, priv *ecdsa.PrivateKey, msg []byte) []byte {
	t.Helper()
	digest := sha512.Sum384(msg)
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
	require.NoError(t, err)
	sig := make([]byte, ES384SignatureSize)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(sig[p384CoordinateSize-len(rBytes):p384CoordinateSize], rBytes)
	copy(sig[ES384SignatureSize-len(sBytes):], sBytes)
	return sig
}

func signMLDSA87(t *testing.T, sk *mldsa87.PrivateKey, msg []byte) []byte {
	t.Helper()
	sig := make([]byte, MLDSA87SignatureSize)
	err := mldsa87.SignTo(sk, msg, nil, false, sig)
	require.NoError(t, err)
	return sig
}

// Tests.

func TestCanonicalAttestationMessageStable(t *testing.T) {
	msg1, err := CanonicalAttestationMessage(testAttestationPayload())
	require.NoError(t, err)
	msg2, err := CanonicalAttestationMessage(testAttestationPayload())
	require.NoError(t, err)
	require.Equal(t, msg1, msg2)
	require.Contains(t, string(msg1), CredAttestPrefix)
}

func TestCanonicalPubkeyBundleMessageStable(t *testing.T) {
	msg1, err := CanonicalPubkeyBundleMessage(testBundlePayload())
	require.NoError(t, err)
	msg2, err := CanonicalPubkeyBundleMessage(testBundlePayload())
	require.NoError(t, err)
	require.Equal(t, msg1, msg2)
	require.Contains(t, string(msg1), PubkeyBundlePrefix)
}

func TestHybridAttestationRoundTrip(t *testing.T) {
	esPriv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	mlPub, mlPriv, err := mldsa87.GenerateKey(rand.Reader)
	require.NoError(t, err)
	mlPubBytes, err := mlPub.MarshalBinary()
	require.NoError(t, err)

	payload := testAttestationPayload()
	msg, err := CanonicalAttestationMessage(payload)
	require.NoError(t, err)
	sigEs := signES384Raw(t, esPriv, msg)
	sigMl := signMLDSA87(t, mlPriv, msg)

	// Both legs valid → pass.
	require.NoError(t, VerifyHybridAttestation(&esPriv.PublicKey, mlPubBytes, payload, sigEs, sigMl))
}

func TestHybridAttestationPartialRejected(t *testing.T) {
	esPriv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	mlPub, mlPriv, err := mldsa87.GenerateKey(rand.Reader)
	require.NoError(t, err)
	mlPubBytes, err := mlPub.MarshalBinary()
	require.NoError(t, err)

	payload := testAttestationPayload()
	msg, err := CanonicalAttestationMessage(payload)
	require.NoError(t, err)
	sigEs := signES384Raw(t, esPriv, msg)
	sigMl := signMLDSA87(t, mlPriv, msg)

	// Tamper ES384 only → fail.
	tampered := append([]byte{}, sigEs...)
	tampered[0] ^= 0xff
	err = VerifyHybridAttestation(&esPriv.PublicKey, mlPubBytes, payload, tampered, sigMl)
	require.ErrorContains(t, err, "ES384")

	// Tamper ML-DSA-87 only → fail.
	tamperedMl := append([]byte{}, sigMl...)
	tamperedMl[0] ^= 0xff
	err = VerifyHybridAttestation(&esPriv.PublicKey, mlPubBytes, payload, sigEs, tamperedMl)
	require.ErrorContains(t, err, "ML-DSA-87")

	// Tamper payload → both legs fail.
	mutated := payload
	mutated.CredentialID = "different"
	err = VerifyHybridAttestation(&esPriv.PublicKey, mlPubBytes, mutated, sigEs, sigMl)
	require.Error(t, err)
	require.ErrorContains(t, err, "ES384")
	require.ErrorContains(t, err, "ML-DSA-87")
}

func TestHybridBundleRoundTripAndTamper(t *testing.T) {
	esPriv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	mlPub, mlPriv, err := mldsa87.GenerateKey(rand.Reader)
	require.NoError(t, err)
	mlPubBytes, err := mlPub.MarshalBinary()
	require.NoError(t, err)

	payload := testBundlePayload()
	msg, err := CanonicalPubkeyBundleMessage(payload)
	require.NoError(t, err)
	sigEs := signES384Raw(t, esPriv, msg)
	sigMl := signMLDSA87(t, mlPriv, msg)

	require.NoError(t, VerifyHybridBundle(&esPriv.PublicKey, mlPubBytes, payload, sigEs, sigMl))

	// Swapping the anchor ES384 pubkey inside the payload breaks both sigs.
	tamp := payload
	tamp.AnchorEs384PublicKey = "malicious"
	err = VerifyHybridBundle(&esPriv.PublicKey, mlPubBytes, tamp, sigEs, sigMl)
	require.Error(t, err)
}

func TestAnchorFingerprintStable(t *testing.T) {
	esPriv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	mlPub, _, err := mldsa87.GenerateKey(rand.Reader)
	require.NoError(t, err)
	mlPubBytes, err := mlPub.MarshalBinary()
	require.NoError(t, err)

	fp1, err := AnchorFingerprint(&esPriv.PublicKey, mlPubBytes)
	require.NoError(t, err)
	fp2, err := AnchorFingerprint(&esPriv.PublicKey, mlPubBytes)
	require.NoError(t, err)
	require.Equal(t, fp1, fp2)
	require.Len(t, fp1, 64) // SHA-256 hex
}

func TestAnchorFingerprintChangesOnTamper(t *testing.T) {
	esPriv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	mlPub, _, err := mldsa87.GenerateKey(rand.Reader)
	require.NoError(t, err)
	mlPubBytes, err := mlPub.MarshalBinary()
	require.NoError(t, err)

	fp1, err := AnchorFingerprint(&esPriv.PublicKey, mlPubBytes)
	require.NoError(t, err)

	// Swap the ML-DSA leg for a different key.
	mlPub2, _, err := mldsa87.GenerateKey(rand.Reader)
	require.NoError(t, err)
	mlPubBytes2, err := mlPub2.MarshalBinary()
	require.NoError(t, err)
	fp2, err := AnchorFingerprint(&esPriv.PublicKey, mlPubBytes2)
	require.NoError(t, err)
	require.NotEqual(t, fp1, fp2)
}

func TestECP384PublicJWKRoundTrip(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	jwk, err := ECP384PublicJWKFromECDSA(&priv.PublicKey)
	require.NoError(t, err)
	require.Equal(t, "EC", jwk.Kty)
	require.Equal(t, "P-384", jwk.Crv)

	pub, err := jwk.ToECDSAPublicKey()
	require.NoError(t, err)
	require.True(t, priv.PublicKey.Equal(pub))
}

func TestECP384PublicJWKValidateRejectsInvalid(t *testing.T) {
	validX := base64.RawURLEncoding.EncodeToString(make([]byte, 48))
	validY := base64.RawURLEncoding.EncodeToString(make([]byte, 48))
	tests := []struct {
		name string
		jwk  ECP384PublicJWK
	}{
		{"private-d-present", ECP384PublicJWK{Kty: "EC", Crv: "P-384", X: validX, Y: validY, D: "secret"}},
		{"wrong-curve", ECP384PublicJWK{Kty: "EC", Crv: "P-256", X: validX, Y: validY}},
		{"extra-kid", ECP384PublicJWK{Kty: "EC", Crv: "P-384", X: validX, Y: validY, Kid: "x"}},
		{"missing-y", ECP384PublicJWK{Kty: "EC", Crv: "P-384", X: validX}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Error(t, tt.jwk.ValidatePublic())
		})
	}
}
