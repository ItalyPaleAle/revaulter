package clientcore

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/italypaleale/revaulter/internal/protocolv2"
)

// signingKeyProofFixture is a signed publication proof plus the anchor that produced it
type signingKeyProofFixture struct {
	anchor  *PinnedAnchor
	payload protocolv2.SigningKeyPublicationPayload
	resp    *SigningPubkeyResponse
}

// newSigningKeyProofFixture mints a fresh hybrid anchor and signs a publication proof binding the given key id
func newSigningKeyProofFixture(t *testing.T, userID, algorithm, keyLabel, keyID string) *signingKeyProofFixture {
	t.Helper()

	esPriv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	mlPriv, err := mldsa.GenerateKey(mldsa.MLDSA87())
	require.NoError(t, err)
	mlPubBytes := mlPriv.PublicKey().Bytes()

	payload := protocolv2.SigningKeyPublicationPayload{
		UserID:          userID,
		Algorithm:       algorithm,
		KeyLabel:        keyLabel,
		KeyID:           keyID,
		WrappedKeyEpoch: 1,
		CreatedAt:       time.Now().Unix(),
		V:               protocolv2.SigningKeyPublicationVersion,
	}
	msg := protocolv2.CanonicalSigningKeyPublicationMessage(&payload)

	return &signingKeyProofFixture{
		anchor: &PinnedAnchor{
			UserID:          userID,
			Es384Pub:        &esPriv.PublicKey,
			Mldsa87PubBytes: mlPubBytes,
		},
		payload: payload,
		resp: &SigningPubkeyResponse{
			Algorithm:                   algorithm,
			KeyLabel:                    keyLabel,
			PublicationPayload:          payload.CanonicalBody(),
			PublicationSignatureEs384:   base64.RawURLEncoding.EncodeToString(testSignES384Raw(t, esPriv, msg)),
			PublicationSignatureMldsa87: base64.RawURLEncoding.EncodeToString(testSignMLDSA87(t, mlPriv, msg)),
		},
	}
}

func testSignES384Raw(t *testing.T, priv *ecdsa.PrivateKey, msg []byte) []byte {
	t.Helper()
	const coordinateSize = 48
	digest := sha512.Sum384(msg)
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
	require.NoError(t, err)
	sig := make([]byte, protocolv2.ES384SignatureSize)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(sig[coordinateSize-len(rBytes):coordinateSize], rBytes)
	copy(sig[protocolv2.ES384SignatureSize-len(sBytes):], sBytes)
	return sig
}

func testSignMLDSA87(t *testing.T, sk *mldsa.PrivateKey, msg []byte) []byte {
	t.Helper()
	sig, err := sk.Sign(rand.Reader, msg, nil)
	require.NoError(t, err)
	return sig
}

// testServer is the server address used in signing key publication tests
const testServer = "https://example.invalid"

// TestVerifySigningKeyPublication covers the binding between the advertised signing key and the pinned anchor
// This is what stops a compromised server from advertising a key of its own choosing, which a user would then copy into an authorized_keys file
func TestVerifySigningKeyPublication(t *testing.T) {
	const (
		userID    = "user-abc"
		keyLabel  = "ssh-main"
		algorithm = protocolv2.SigningAlgES256
		keyID     = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU"
	)

	t.Run("accepts a proof signed by the pinned anchor", func(t *testing.T) {
		fx := newSigningKeyProofFixture(t, userID, algorithm, keyLabel, keyID)

		require.NoError(t, verifySigningKeyPublication(fx.anchor, fx.resp, keyID, keyLabel, algorithm, testServer))
	})

	t.Run("rejects an auto-stored key that carries no proof", func(t *testing.T) {
		fx := newSigningKeyProofFixture(t, userID, algorithm, keyLabel, keyID)

		for _, field := range []string{"payload", "es384", "mldsa87"} {
			t.Run("missing-"+field, func(t *testing.T) {
				resp := *fx.resp
				switch field {
				case "payload":
					resp.PublicationPayload = ""
				case "es384":
					resp.PublicationSignatureEs384 = ""
				case "mldsa87":
					resp.PublicationSignatureMldsa87 = ""
				}

				err := verifySigningKeyPublication(fx.anchor, &resp, keyID, keyLabel, algorithm, testServer)
				require.ErrorContains(t, err, "no publication proof")
			})
		}
	})

	t.Run("rejects a proof signed by a different anchor", func(t *testing.T) {
		fx := newSigningKeyProofFixture(t, userID, algorithm, keyLabel, keyID)
		// A malicious server can mint its own anchor and sign a well-formed proof with it
		attacker := newSigningKeyProofFixture(t, userID, algorithm, keyLabel, keyID)

		err := verifySigningKeyPublication(fx.anchor, attacker.resp, keyID, keyLabel, algorithm, testServer)
		require.ErrorContains(t, err, "not valid")
	})

	t.Run("rejects a proof bound to a different key id", func(t *testing.T) {
		// The proof is internally consistent, but covers a key other than the one the server just served
		fx := newSigningKeyProofFixture(t, userID, algorithm, keyLabel, "some-other-key-id")

		err := verifySigningKeyPublication(fx.anchor, fx.resp, keyID, keyLabel, algorithm, testServer)
		require.ErrorContains(t, err, "keyId")
	})

	t.Run("rejects a proof bound to a different key label", func(t *testing.T) {
		fx := newSigningKeyProofFixture(t, userID, algorithm, "a-different-label", keyID)

		err := verifySigningKeyPublication(fx.anchor, fx.resp, keyID, keyLabel, algorithm, testServer)
		require.ErrorContains(t, err, "keyLabel")
	})

	t.Run("rejects a proof bound to a different algorithm", func(t *testing.T) {
		fx := newSigningKeyProofFixture(t, userID, protocolv2.SigningAlgEd25519, keyLabel, keyID)

		err := verifySigningKeyPublication(fx.anchor, fx.resp, keyID, keyLabel, algorithm, testServer)
		require.ErrorContains(t, err, "algorithm")
	})

	t.Run("rejects a proof issued for a different user", func(t *testing.T) {
		fx := newSigningKeyProofFixture(t, "someone-else", algorithm, keyLabel, keyID)
		// The anchor is pinned per (server, userId), so the pinned userId is the one the agent expects
		fx.anchor.UserID = userID

		err := verifySigningKeyPublication(fx.anchor, fx.resp, keyID, keyLabel, algorithm, testServer)
		require.ErrorContains(t, err, "userId")
	})

	t.Run("skips verification when anchor pinning is disabled", func(t *testing.T) {
		// --no-trust-store leaves no trusted anchor to verify against, so there is nothing to check
		require.NoError(t, verifySigningKeyPublication(nil, &SigningPubkeyResponse{}, keyID, keyLabel, algorithm, testServer))
	})
}
