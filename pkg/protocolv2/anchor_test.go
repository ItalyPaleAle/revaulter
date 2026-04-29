package protocolv2

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	"github.com/stretchr/testify/require"
)

// Helpers.

func testAttestationPayload() *AttestationPayload {
	return &AttestationPayload{
		UserID:                  "user-123",
		CredentialID:            "cred-abc",
		CredentialPublicKeyHash: base64.RawURLEncoding.EncodeToString([]byte("cred-public-key-hash-bytes")),
		WrappedKeyEpoch:         1,
		CreatedAt:               1720000000,
	}
}

func testBundlePayload() *PubkeyBundlePayload {
	return &PubkeyBundlePayload{
		UserID:                 "user-123",
		RequestEncEcdhPubkey:   `{"kty":"EC","crv":"P-256","x":"xxx","y":"yyy"}`,
		RequestEncMlkemPubkey:  base64.RawURLEncoding.EncodeToString([]byte("mlkem-pub-bytes")),
		AnchorEs384Crv:         "P-384",
		AnchorEs384Kty:         "EC",
		AnchorEs384X:           "aaa",
		AnchorEs384Y:           "bbb",
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
	msg1 := CanonicalAttestationMessage(testAttestationPayload())
	msg2 := CanonicalAttestationMessage(testAttestationPayload())
	require.Equal(t, msg1, msg2)
	require.Contains(t, string(msg1), CredAttestPrefix)
}

func TestAttestationPayloadCanonicalBody(t *testing.T) {
	body := testAttestationPayload().CanonicalBody()
	expected := "userId=user-123\n" +
		"credentialId=cred-abc\n" +
		"credentialPublicKeyHash=" + base64.RawURLEncoding.EncodeToString([]byte("cred-public-key-hash-bytes")) + "\n" +
		"wrappedKeyEpoch=1\n" +
		"createdAt=1720000000"
	require.Equal(t, expected, body)
}

func TestAttestationPayloadValidateCreatedAt(t *testing.T) {
	now, _ := time.Parse(time.RFC3339, "2026-01-01T01:00:00Z")
	skew := 2 * time.Minute

	t.Run("accepts a payload exactly at server now", func(t *testing.T) {
		p := AttestationPayload{
			CreatedAt: now.Unix(),
		}
		require.NoError(t, p.ValidateCreatedAt(now, skew))
	})

	t.Run("accepts a payload near the lower bound", func(t *testing.T) {
		p := AttestationPayload{
			CreatedAt: now.Add(-skew + time.Second).Unix(),
		}
		require.NoError(t, p.ValidateCreatedAt(now, skew))
	})

	t.Run("accepts a payload near the upper bound", func(t *testing.T) {
		p := AttestationPayload{
			CreatedAt: now.Add(skew - time.Second).Unix(),
		}
		require.NoError(t, p.ValidateCreatedAt(now, skew))
	})

	t.Run("rejects a payload older than the window", func(t *testing.T) {
		p := AttestationPayload{
			CreatedAt: now.Add(-skew - time.Second).Unix(),
		}
		err := p.ValidateCreatedAt(now, skew)
		require.Error(t, err)
		require.Contains(t, err.Error(), "outside the ±2m0s acceptance window")
	})

	t.Run("rejects a payload from the future beyond the window", func(t *testing.T) {
		p := AttestationPayload{
			CreatedAt: now.Add(skew + time.Second).Unix(),
		}
		err := p.ValidateCreatedAt(now, skew)
		require.Error(t, err)
		require.Contains(t, err.Error(), "outside the ±2m0s acceptance window")
	})

	t.Run("rejects a missing or non-positive createdAt", func(t *testing.T) {
		p := AttestationPayload{
			CreatedAt: 0,
		}
		err := p.ValidateCreatedAt(now, skew)
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing or non-positive")

		p = AttestationPayload{
			CreatedAt: -1,
		}
		err = p.ValidateCreatedAt(now, skew)
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing or non-positive")
	})

	t.Run("rejects a non-positive skew (development guard)", func(t *testing.T) {
		p := AttestationPayload{
			CreatedAt: now.Unix(),
		}
		err := p.ValidateCreatedAt(now, 0)
		require.Error(t, err)
		require.Contains(t, err.Error(), "skew must be positive")
	})
}

func TestParseAttestationPayloadRoundTrip(t *testing.T) {
	in := testAttestationPayload()
	out, err := ParseAttestationPayload(in.CanonicalBody())
	require.NoError(t, err)
	require.Equal(t, *in, out)
}

func TestParseAttestationPayloadRejectsMalformed(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{"missing-line", "userId=u\ncredentialId=c\ncredentialPublicKeyHash=k\nwrappedKeyEpoch=1"},
		{"extra-line", testAttestationPayload().CanonicalBody() + "\nextra=x"},
		{"wrong-key-order", "credentialId=c\nuserId=u\ncredentialPublicKeyHash=k\nwrappedKeyEpoch=1\ncreatedAt=2"},
		{"missing-equals", "userId u\ncredentialId=c\ncredentialPublicKeyHash=k\nwrappedKeyEpoch=1\ncreatedAt=2"},
		{"non-integer-epoch", "userId=u\ncredentialId=c\ncredentialPublicKeyHash=k\nwrappedKeyEpoch=not-a-number\ncreatedAt=2"},
		{"non-integer-created-at", "userId=u\ncredentialId=c\ncredentialPublicKeyHash=k\nwrappedKeyEpoch=1\ncreatedAt=not-a-number"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseAttestationPayload(tt.body)
			require.Error(t, err)
		})
	}
}

func TestCanonicalPubkeyBundleMessageStable(t *testing.T) {
	msg1 := CanonicalPubkeyBundleMessage(testBundlePayload())
	msg2 := CanonicalPubkeyBundleMessage(testBundlePayload())
	require.Equal(t, msg1, msg2)
	require.Contains(t, string(msg1), PubkeyBundlePrefix)
}

func TestPubkeyBundlePayloadCanonicalBody(t *testing.T) {
	body := testBundlePayload().CanonicalBody()
	expected := "userId=user-123\n" +
		`requestEncEcdhPubkey={"kty":"EC","crv":"P-256","x":"xxx","y":"yyy"}` + "\n" +
		"requestEncMlkemPubkey=" + base64.RawURLEncoding.EncodeToString([]byte("mlkem-pub-bytes")) + "\n" +
		"anchorEs384Crv=P-384\n" +
		"anchorEs384Kty=EC\n" +
		"anchorEs384X=aaa\n" +
		"anchorEs384Y=bbb\n" +
		"anchorMldsa87PublicKey=" + base64.RawURLEncoding.EncodeToString([]byte("mldsa87-pub-bytes")) + "\n" +
		"wrappedKeyEpoch=1"
	require.Equal(t, expected, body)
}

func TestParsePubkeyBundlePayloadRoundTrip(t *testing.T) {
	in := testBundlePayload()
	out, err := ParsePubkeyBundlePayload(in.CanonicalBody())
	require.NoError(t, err)
	require.Equal(t, *in, out)
}

func TestParsePubkeyBundlePayloadRejectsMalformed(t *testing.T) {
	good := testBundlePayload().CanonicalBody()
	tests := []struct {
		name string
		body string
	}{
		{"missing-line", strings.Join(strings.Split(good, "\n")[:8], "\n")},
		{"extra-line", good + "\nextra=x"},
		{"wrong-key-order", "requestEncEcdhPubkey=x\nuserId=u\nrequestEncMlkemPubkey=x\nanchorEs384Crv=P-384\nanchorEs384Kty=EC\nanchorEs384X=a\nanchorEs384Y=b\nanchorMldsa87PublicKey=x\nwrappedKeyEpoch=1"},
		{"missing-equals", "userId u\nrequestEncEcdhPubkey=x\nrequestEncMlkemPubkey=x\nanchorEs384Crv=P-384\nanchorEs384Kty=EC\nanchorEs384X=a\nanchorEs384Y=b\nanchorMldsa87PublicKey=x\nwrappedKeyEpoch=1"},
		{"non-integer-epoch", "userId=u\nrequestEncEcdhPubkey=x\nrequestEncMlkemPubkey=x\nanchorEs384Crv=P-384\nanchorEs384Kty=EC\nanchorEs384X=a\nanchorEs384Y=b\nanchorMldsa87PublicKey=x\nwrappedKeyEpoch=nope"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParsePubkeyBundlePayload(tt.body)
			require.Error(t, err)
		})
	}
}

func TestHybridAttestationRoundTrip(t *testing.T) {
	esPriv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	mlPub, mlPriv, err := mldsa87.GenerateKey(rand.Reader)
	require.NoError(t, err)
	mlPubBytes, err := mlPub.MarshalBinary()
	require.NoError(t, err)

	payload := testAttestationPayload()
	msg := CanonicalAttestationMessage(payload)
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
	msg := CanonicalAttestationMessage(payload)
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
	msg := CanonicalPubkeyBundleMessage(payload)
	sigEs := signES384Raw(t, esPriv, msg)
	sigMl := signMLDSA87(t, mlPriv, msg)

	require.NoError(t, VerifyHybridBundle(&esPriv.PublicKey, mlPubBytes, payload, sigEs, sigMl))

	// Swapping the anchor ES384 pubkey inside the payload breaks both sigs.
	tamp := payload
	tamp.AnchorEs384X = "malicious"
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
