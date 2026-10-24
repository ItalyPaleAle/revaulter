package protocolv2

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func testAttestationPayloadV2() *AttestationPayloadV2 {
	return &AttestationPayloadV2{
		UserID:                  "user-123",
		CredentialID:            b64([]byte("cred-id-16-bytes")),
		CredentialType:          CredentialTypeDevice,
		CredentialPublicKeyHash: b64([]byte("hash-of-device-keys")),
		WrappedKeyEpoch:         2,
		CreatedAt:               1761300000,
		V:                       AttestationVersion2,
	}
}

func TestAttestationPayloadV2CanonicalBody(t *testing.T) {
	expected := "userId=user-123\n" +
		"credentialId=" + b64([]byte("cred-id-16-bytes")) + "\n" +
		"credentialType=device\n" +
		"credentialPublicKeyHash=" + b64([]byte("hash-of-device-keys")) + "\n" +
		"wrappedKeyEpoch=2\n" +
		"createdAt=1761300000\n" +
		"v=2"
	require.Equal(t, expected, testAttestationPayloadV2().CanonicalBody())
	require.Equal(t, CredAttestPrefix+expected, string(CanonicalAttestationMessageV2(testAttestationPayloadV2())))
}

func TestParseAttestationPayloadV2(t *testing.T) {
	t.Run("round trip", func(t *testing.T) {
		p := testAttestationPayloadV2()
		parsed, err := ParseAttestationPayloadV2(p.CanonicalBody())
		require.NoError(t, err)
		require.Equal(t, *p, parsed)
	})

	t.Run("rejects another version", func(t *testing.T) {
		p := testAttestationPayloadV2()
		p.V = 3
		_, err := ParseAttestationPayloadV2(p.CanonicalBody())
		require.Error(t, err)
		require.ErrorContains(t, err, "unsupported attestation version")
	})

	t.Run("rejects an unknown credential type", func(t *testing.T) {
		p := testAttestationPayloadV2()
		p.CredentialType = "security-key"
		_, err := ParseAttestationPayloadV2(p.CanonicalBody())
		require.Error(t, err)
		require.ErrorContains(t, err, "unsupported credential type")
	})

	t.Run("v1 and v2 bodies don't parse as each other", func(t *testing.T) {
		_, err := ParseAttestationPayloadV2(testAttestationPayload().CanonicalBody())
		require.Error(t, err)

		_, err = ParseAttestationPayload(testAttestationPayloadV2().CanonicalBody())
		require.Error(t, err)
	})
}

func TestAttestationPayloadVersion(t *testing.T) {
	v, err := AttestationPayloadVersion(testAttestationPayload().CanonicalBody())
	require.NoError(t, err)
	require.Equal(t, AttestationVersion1, v)

	v, err = AttestationPayloadVersion(testAttestationPayloadV2().CanonicalBody())
	require.NoError(t, err)
	require.Equal(t, AttestationVersion2, v)

	_, err = AttestationPayloadVersion("userId=a\nv=two")
	require.Error(t, err)
}

func TestAttestationPayloadV2ValidateCreatedAt(t *testing.T) {
	now := time.Unix(1761300000, 0)
	p := testAttestationPayloadV2()

	err := p.ValidateCreatedAt(now.Add(time.Minute), 2*time.Minute)
	require.NoError(t, err)

	err = p.ValidateCreatedAt(now.Add(3*time.Minute), 2*time.Minute)
	require.Error(t, err)
}

func TestVerifyHybridAttestationV2(t *testing.T) {
	esPriv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	mlPriv, err := mldsa.GenerateKey(mldsa.MLDSA87())
	require.NoError(t, err)
	mlPub := mlPriv.PublicKey().Bytes()

	payload := testAttestationPayloadV2()
	msg := CanonicalAttestationMessageV2(payload)
	sigEs := signES384Raw(t, esPriv, msg)
	sigMl := signMLDSA87(t, mlPriv, msg)

	t.Run("accepts valid signatures", func(t *testing.T) {
		err := VerifyHybridAttestationV2(&esPriv.PublicKey, mlPub, payload, sigEs, sigMl)
		require.NoError(t, err)
	})

	t.Run("binds the credential type", func(t *testing.T) {
		other := *payload
		other.CredentialType = CredentialTypePasskey
		err := VerifyHybridAttestationV2(&esPriv.PublicKey, mlPub, &other, sigEs, sigMl)
		require.Error(t, err)
		require.ErrorContains(t, err, "ES384")
		require.ErrorContains(t, err, "ML-DSA-87")
	})

	t.Run("rejects a v1 signature over the same fields", func(t *testing.T) {
		v1 := &AttestationPayload{
			UserID:                  payload.UserID,
			CredentialID:            payload.CredentialID,
			CredentialPublicKeyHash: payload.CredentialPublicKeyHash,
			WrappedKeyEpoch:         payload.WrappedKeyEpoch,
			CreatedAt:               payload.CreatedAt,
		}
		v1Msg := CanonicalAttestationMessage(v1)
		err := VerifyHybridAttestationV2(&esPriv.PublicKey, mlPub, payload, signES384Raw(t, esPriv, v1Msg), signMLDSA87(t, mlPriv, v1Msg))
		require.Error(t, err)
	})

	t.Run("rejects an unknown version", func(t *testing.T) {
		other := *payload
		other.V = 3
		err := VerifyHybridAttestationV2(&esPriv.PublicKey, mlPub, &other, sigEs, sigMl)
		require.Error(t, err)
		require.ErrorContains(t, err, "unsupported attestation version")
	})

	t.Run("rejects an unknown credential type", func(t *testing.T) {
		other := *payload
		other.CredentialType = ""
		err := VerifyHybridAttestationV2(&esPriv.PublicKey, mlPub, &other, sigEs, sigMl)
		require.Error(t, err)
		require.ErrorContains(t, err, "unsupported credential type")
	})
}
