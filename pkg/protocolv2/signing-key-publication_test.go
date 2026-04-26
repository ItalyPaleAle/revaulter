package protocolv2

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	"github.com/stretchr/testify/require"
)

func testSigningKeyPublicationPayload() *SigningKeyPublicationPayload {
	return &SigningKeyPublicationPayload{
		UserID:          "user-pub-1",
		Algorithm:       "ES256",
		KeyLabel:        "release-signing",
		KeyID:           "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		WrappedKeyEpoch: 1,
		CreatedAt:       1730000000,
		V:               SigningKeyPublicationVersion,
	}
}

func TestSigningKeyPublicationCanonicalBody(t *testing.T) {
	body := testSigningKeyPublicationPayload().CanonicalBody()
	expected := "userId=user-pub-1\n" +
		"algorithm=ES256\n" +
		"keyLabel=release-signing\n" +
		"keyId=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n" +
		"wrappedKeyEpoch=1\n" +
		"createdAt=1730000000\n" +
		"v=1"
	require.Equal(t, expected, body)
}

func TestSigningKeyPublicationCanonicalMessageStable(t *testing.T) {
	msg1 := CanonicalSigningKeyPublicationMessage(testSigningKeyPublicationPayload())
	msg2 := CanonicalSigningKeyPublicationMessage(testSigningKeyPublicationPayload())
	require.Equal(t, msg1, msg2)
	require.Contains(t, string(msg1), SigningKeyPublicationPrefix)
}

func TestParseSigningKeyPublicationPayloadRoundTrip(t *testing.T) {
	in := testSigningKeyPublicationPayload()
	out, err := ParseSigningKeyPublicationPayload(in.CanonicalBody())
	require.NoError(t, err)
	require.Equal(t, *in, out)
}

func TestParseSigningKeyPublicationPayloadRejectsMalformed(t *testing.T) {
	good := testSigningKeyPublicationPayload().CanonicalBody()
	tests := []struct {
		name string
		body string
	}{
		{"missing-line", strings.Join(strings.Split(good, "\n")[:6], "\n")},
		{"extra-line", good + "\nextra=x"},
		{"wrong-key-order", "algorithm=ES256\nuserId=u\nkeyLabel=k\nkeyId=k\nwrappedKeyEpoch=1\ncreatedAt=2\nv=1"},
		{"missing-equals", "userId u\nalgorithm=ES256\nkeyLabel=k\nkeyId=k\nwrappedKeyEpoch=1\ncreatedAt=2\nv=1"},
		{"non-integer-epoch", "userId=u\nalgorithm=ES256\nkeyLabel=k\nkeyId=k\nwrappedKeyEpoch=nope\ncreatedAt=2\nv=1"},
		{"non-integer-created-at", "userId=u\nalgorithm=ES256\nkeyLabel=k\nkeyId=k\nwrappedKeyEpoch=1\ncreatedAt=nope\nv=1"},
		{"non-integer-v", "userId=u\nalgorithm=ES256\nkeyLabel=k\nkeyId=k\nwrappedKeyEpoch=1\ncreatedAt=2\nv=nope"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseSigningKeyPublicationPayload(tt.body)
			require.Error(t, err)
		})
	}
}

func TestSigningKeyPublicationValidateCreatedAt(t *testing.T) {
	now, _ := time.Parse(time.RFC3339, "2026-04-25T12:00:00Z")
	skew := 2 * time.Minute

	t.Run("accepts a payload exactly at server now", func(t *testing.T) {
		p := SigningKeyPublicationPayload{CreatedAt: now.Unix()}
		require.NoError(t, p.ValidateCreatedAt(now, skew))
	})

	t.Run("accepts near the lower bound", func(t *testing.T) {
		p := SigningKeyPublicationPayload{CreatedAt: now.Add(-skew + time.Second).Unix()}
		require.NoError(t, p.ValidateCreatedAt(now, skew))
	})

	t.Run("rejects older than the window", func(t *testing.T) {
		p := SigningKeyPublicationPayload{CreatedAt: now.Add(-skew - time.Second).Unix()}
		err := p.ValidateCreatedAt(now, skew)
		require.ErrorContains(t, err, "outside the ±2m0s acceptance window")
	})

	t.Run("rejects future beyond the window", func(t *testing.T) {
		p := SigningKeyPublicationPayload{CreatedAt: now.Add(skew + time.Second).Unix()}
		err := p.ValidateCreatedAt(now, skew)
		require.ErrorContains(t, err, "outside the ±2m0s acceptance window")
	})

	t.Run("rejects missing or non-positive createdAt", func(t *testing.T) {
		p := SigningKeyPublicationPayload{CreatedAt: 0}
		err := p.ValidateCreatedAt(now, skew)
		require.ErrorContains(t, err, "missing or non-positive")
	})

	t.Run("rejects non-positive skew", func(t *testing.T) {
		p := SigningKeyPublicationPayload{CreatedAt: now.Unix()}
		err := p.ValidateCreatedAt(now, 0)
		require.ErrorContains(t, err, "skew must be positive")
	})
}

func TestHybridSigningKeyPublicationRoundTrip(t *testing.T) {
	esPriv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	mlPub, mlPriv, err := mldsa87.GenerateKey(rand.Reader)
	require.NoError(t, err)
	mlPubBytes, err := mlPub.MarshalBinary()
	require.NoError(t, err)

	payload := testSigningKeyPublicationPayload()
	msg := CanonicalSigningKeyPublicationMessage(payload)
	sigEs := signES384Raw(t, esPriv, msg)
	sigMl := signMLDSA87(t, mlPriv, msg)

	require.NoError(t, VerifyHybridSigningKeyPublication(&esPriv.PublicKey, mlPubBytes, payload, sigEs, sigMl))
}

func TestHybridSigningKeyPublicationRejectsTamper(t *testing.T) {
	esPriv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	mlPub, mlPriv, err := mldsa87.GenerateKey(rand.Reader)
	require.NoError(t, err)
	mlPubBytes, err := mlPub.MarshalBinary()
	require.NoError(t, err)

	payload := testSigningKeyPublicationPayload()
	msg := CanonicalSigningKeyPublicationMessage(payload)
	sigEs := signES384Raw(t, esPriv, msg)
	sigMl := signMLDSA87(t, mlPriv, msg)

	t.Run("tampered ES384 fails", func(t *testing.T) {
		t.Parallel()
		tampered := append([]byte{}, sigEs...)
		tampered[0] ^= 0xff
		err := VerifyHybridSigningKeyPublication(&esPriv.PublicKey, mlPubBytes, payload, tampered, sigMl)
		require.ErrorContains(t, err, "ES384")
	})

	t.Run("tampered ML-DSA-87 fails", func(t *testing.T) {
		t.Parallel()
		tampered := append([]byte{}, sigMl...)
		tampered[0] ^= 0xff
		err := VerifyHybridSigningKeyPublication(&esPriv.PublicKey, mlPubBytes, payload, sigEs, tampered)
		require.ErrorContains(t, err, "ML-DSA-87")
	})

	t.Run("payload mutation breaks both legs", func(t *testing.T) {
		t.Parallel()
		mutated := *payload
		mutated.KeyID = "0000000000000000000000000000000000000000000000000000000000000000"
		err := VerifyHybridSigningKeyPublication(&esPriv.PublicKey, mlPubBytes, &mutated, sigEs, sigMl)
		require.Error(t, err)
		require.ErrorContains(t, err, "ES384")
		require.ErrorContains(t, err, "ML-DSA-87")
	})

	t.Run("wrong domain prefix breaks verification", func(t *testing.T) {
		t.Parallel()
		// Sign over a message that uses the credential-attestation prefix instead of the publication one
		// A verifier that doesn't enforce domain separation would accept this signature
		wrongMsg := append([]byte(CredAttestPrefix), payload.CanonicalBody()...)
		wrongEs := signES384Raw(t, esPriv, wrongMsg)
		wrongMl := signMLDSA87(t, mlPriv, wrongMsg)
		err := VerifyHybridSigningKeyPublication(&esPriv.PublicKey, mlPubBytes, payload, wrongEs, wrongMl)
		require.Error(t, err)
	})
}

func TestVerifySigningKeyPublicResponse(t *testing.T) {
	esPriv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	mlPub, mlPriv, err := mldsa87.GenerateKey(rand.Reader)
	require.NoError(t, err)
	mlPubBytes, err := mlPub.MarshalBinary()
	require.NoError(t, err)

	payload := testSigningKeyPublicationPayload()
	body := payload.CanonicalBody()
	msg := CanonicalSigningKeyPublicationMessage(payload)
	sigEs := signES384Raw(t, esPriv, msg)
	sigMl := signMLDSA87(t, mlPriv, msg)
	sigEsB64 := base64.RawURLEncoding.EncodeToString(sigEs)
	sigMlB64 := base64.RawURLEncoding.EncodeToString(sigMl)

	t.Run("accepts a valid response against the pinned anchor", func(t *testing.T) {
		out, err := VerifySigningKeyPublicResponse(body, sigEsB64, sigMlB64, SigningKeyPublicResponseVerifyOptions{
			Es384Pub:          &esPriv.PublicKey,
			Mldsa87PubBytes:   mlPubBytes,
			ExpectedUserID:    payload.UserID,
			ExpectedAlgorithm: payload.Algorithm,
			ExpectedKeyID:     payload.KeyID,
		})
		require.NoError(t, err)
		require.Equal(t, *payload, out)
	})

	t.Run("rejects a missing publication proof", func(t *testing.T) {
		_, err := VerifySigningKeyPublicResponse("", sigEsB64, sigMlB64, SigningKeyPublicResponseVerifyOptions{
			Es384Pub:        &esPriv.PublicKey,
			Mldsa87PubBytes: mlPubBytes,
		})
		require.ErrorContains(t, err, "missing the publication proof")
	})

	t.Run("rejects a nil ES384 pubkey", func(t *testing.T) {
		_, err := VerifySigningKeyPublicResponse(body, sigEsB64, sigMlB64, SigningKeyPublicResponseVerifyOptions{
			Mldsa87PubBytes: mlPubBytes,
		})
		require.ErrorContains(t, err, "pinned ES384 anchor")
	})

	t.Run("rejects a substituted anchor pubkey", func(t *testing.T) {
		// An attacker who controls the response can supply attacker-owned pubkeys + matching signatures
		// Verifying against THOSE pubkeys would succeed; verifying against the pinned ones must fail
		otherPriv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		require.NoError(t, err)
		_, err = VerifySigningKeyPublicResponse(body, sigEsB64, sigMlB64, SigningKeyPublicResponseVerifyOptions{
			Es384Pub:        &otherPriv.PublicKey,
			Mldsa87PubBytes: mlPubBytes,
		})
		require.ErrorContains(t, err, "signature verification failed")
	})

	t.Run("rejects mismatched keyId", func(t *testing.T) {
		_, err := VerifySigningKeyPublicResponse(body, sigEsB64, sigMlB64, SigningKeyPublicResponseVerifyOptions{
			Es384Pub:        &esPriv.PublicKey,
			Mldsa87PubBytes: mlPubBytes,
			ExpectedKeyID:   "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		})
		require.ErrorContains(t, err, "keyId")
	})

	t.Run("rejects mismatched userId", func(t *testing.T) {
		_, err := VerifySigningKeyPublicResponse(body, sigEsB64, sigMlB64, SigningKeyPublicResponseVerifyOptions{
			Es384Pub:        &esPriv.PublicKey,
			Mldsa87PubBytes: mlPubBytes,
			ExpectedUserID:  "different-user",
		})
		require.ErrorContains(t, err, "userId")
	})

	t.Run("rejects unsupported version", func(t *testing.T) {
		bumped := *payload
		bumped.V = 99
		bumpedBody := bumped.CanonicalBody()
		bumpedMsg := CanonicalSigningKeyPublicationMessage(&bumped)
		bumpedEs := base64.RawURLEncoding.EncodeToString(signES384Raw(t, esPriv, bumpedMsg))
		bumpedMl := base64.RawURLEncoding.EncodeToString(signMLDSA87(t, mlPriv, bumpedMsg))
		_, err := VerifySigningKeyPublicResponse(bumpedBody, bumpedEs, bumpedMl, SigningKeyPublicResponseVerifyOptions{
			Es384Pub:        &esPriv.PublicKey,
			Mldsa87PubBytes: mlPubBytes,
		})
		require.ErrorContains(t, err, "unsupported publication version")
	})
}
