//go:build unit

package cmd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	"github.com/stretchr/testify/require"

	"github.com/italypaleale/revaulter/pkg/protocolv2"
)

func newTestAnchorPubkeys(t *testing.T) (*ecdsa.PublicKey, string, []byte, string) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	jwk, err := protocolv2.ECP384PublicJWKFromECDSA(&priv.PublicKey)
	require.NoError(t, err)
	jwkBody := jwk.CanonicalBody()

	mlPub, _, err := mldsa87.GenerateKey(rand.Reader)
	require.NoError(t, err)
	mlPubBytes, err := mlPub.MarshalBinary()
	require.NoError(t, err)
	mlPubB64 := base64.RawURLEncoding.EncodeToString(mlPubBytes)

	return &priv.PublicKey, jwkBody, mlPubBytes, mlPubB64
}

func TestTrustStorePinAndReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "trust.json")

	ts, err := loadTrustStore(path)
	require.NoError(t, err)
	require.Empty(t, ts.Entries)

	es384Pub, es384Raw, mlPubBytes, mlPubB64 := newTestAnchorPubkeys(t)

	// First contact — accept
	pinned, err := ts.checkOrPinAnchor("https://example.test", "user-1", es384Pub, es384Raw, mlPubB64, mlPubBytes,
		func(fp string) (bool, error) {
			require.NotEmpty(t, fp)
			return true, nil
		})
	require.NoError(t, err)
	require.True(t, pinned)

	err = saveTrustStore(path, ts)
	require.NoError(t, err)

	// Reload — subsequent match must not re-prompt
	ts2, err := loadTrustStore(path)
	require.NoError(t, err)
	prompted := false
	pinned, err = ts2.checkOrPinAnchor("https://example.test", "user-1", es384Pub, es384Raw, mlPubB64, mlPubBytes,
		func(string) (bool, error) {
			prompted = true
			return false, nil
		})
	require.NoError(t, err)
	require.False(t, pinned)
	require.False(t, prompted, "confirm must not be invoked for a matching pin")
}

func TestTrustStoreRejectsMismatch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "trust.json")

	ts, err := loadTrustStore(path)
	require.NoError(t, err)

	es384PubA, es384RawA, mlPubBytesA, mlPubB64A := newTestAnchorPubkeys(t)
	es384PubB, es384RawB, mlPubBytesB, mlPubB64B := newTestAnchorPubkeys(t)

	_, err = ts.checkOrPinAnchor("https://example.test", "user-1", es384PubA, es384RawA, mlPubB64A, mlPubBytesA,
		func(string) (bool, error) { return true, nil })
	require.NoError(t, err)
	require.NoError(t, saveTrustStore(path, ts))

	// Mismatch in ML-DSA-87 half must be caught
	ts2, err := loadTrustStore(path)
	require.NoError(t, err)
	_, err = ts2.checkOrPinAnchor("https://example.test", "user-1", es384PubA, es384RawA, mlPubB64B, mlPubBytesB,
		func(string) (bool, error) { return true, nil })
	require.Error(t, err)

	// Mismatch in ES384 half must also be caught
	ts3, err := loadTrustStore(path)
	require.NoError(t, err)
	_, err = ts3.checkOrPinAnchor("https://example.test", "user-1", es384PubB, es384RawB, mlPubB64A, mlPubBytesA,
		func(string) (bool, error) { return true, nil })
	require.Error(t, err)
}

func TestTrustStoreAnchorMismatchRefusesSilentRepin(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "trust.json")

	ts, err := loadTrustStore(path)
	require.NoError(t, err)

	es384PubA, es384RawA, mlPubBytesA, mlPubB64A := newTestAnchorPubkeys(t)
	es384PubB, es384RawB, mlPubBytesB, mlPubB64B := newTestAnchorPubkeys(t)

	// Pin anchor A for user-1
	_, err = ts.checkOrPinAnchor("https://example.test", "user-1", es384PubA, es384RawA, mlPubB64A, mlPubBytesA,
		func(string) (bool, error) { return true, nil })
	require.NoError(t, err)
	require.NoError(t, saveTrustStore(path, ts))

	// Server now presents anchor B — even if a confirm handler would say "yes", the trust store must refuse rather than silently re-pin
	ts2, err := loadTrustStore(path)
	require.NoError(t, err)
	_, err = ts2.checkOrPinAnchor("https://example.test", "user-1", es384PubB, es384RawB, mlPubB64B, mlPubBytesB,
		func(string) (bool, error) { return true, nil })
	require.Error(t, err)
	require.ErrorContains(t, err, "fingerprint mismatch")
	require.ErrorContains(t, err, path)

	// Disk state must still contain the ORIGINAL pin, not the presented one
	ts3, err := loadTrustStore(path)
	require.NoError(t, err)
	entry, ok := ts3.Entries[trustStoreKey("https://example.test", "user-1")]
	require.True(t, ok)
	require.Equal(t, mlPubB64A, entry.AnchorMldsa87PublicKey, "pin must not have been silently rewritten")
}

func TestTrustStoreDistinctPinsPerUserID(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "trust.json")

	ts, err := loadTrustStore(path)
	require.NoError(t, err)

	es384PubA, es384RawA, mlPubBytesA, mlPubB64A := newTestAnchorPubkeys(t)
	es384PubB, es384RawB, mlPubBytesB, mlPubB64B := newTestAnchorPubkeys(t)

	// Different userIds on the same server must get independent pins
	pinned, err := ts.checkOrPinAnchor("https://example.test", "user-1", es384PubA, es384RawA, mlPubB64A, mlPubBytesA,
		func(string) (bool, error) { return true, nil })
	require.NoError(t, err)
	require.True(t, pinned)

	pinned, err = ts.checkOrPinAnchor("https://example.test", "user-2", es384PubB, es384RawB, mlPubB64B, mlPubBytesB,
		func(string) (bool, error) { return true, nil })
	require.NoError(t, err)
	require.True(t, pinned, "a second user on the same server must pin separately, not match user-1's pin")

	require.Len(t, ts.Entries, 2)

	// Each user must see its own anchor when re-checked
	_, err = ts.checkOrPinAnchor("https://example.test", "user-1", es384PubA, es384RawA, mlPubB64A, mlPubBytesA, nil)
	require.NoError(t, err)
	_, err = ts.checkOrPinAnchor("https://example.test", "user-2", es384PubB, es384RawB, mlPubB64B, mlPubBytesB, nil)
	require.NoError(t, err)
}

func TestTrustStoreFailsClosedOnNoConfirm(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "trust.json")

	ts, err := loadTrustStore(path)
	require.NoError(t, err)

	es384Pub, es384Raw, mlPubBytes, mlPubB64 := newTestAnchorPubkeys(t)

	_, err = ts.checkOrPinAnchor("https://example.test", "user-1", es384Pub, es384Raw, mlPubB64, mlPubBytes, nil)
	require.Error(t, err, "first contact with nil confirmer must refuse")
}

// signTestBundle signs a pubkey-bundle payload with both anchor legs and returns base64url-encoded signatures, mirroring what the browser produces at signup
func signTestBundle(t *testing.T, esPriv *ecdsa.PrivateKey, mlPriv *mldsa87.PrivateKey, payload *protocolv2.PubkeyBundlePayload) (sigEsB64, sigMlB64 string) {
	t.Helper()

	msg := protocolv2.CanonicalPubkeyBundleMessage(payload)

	digest := sha512.Sum384(msg)
	r, s, err := ecdsa.Sign(rand.Reader, esPriv, digest[:])
	require.NoError(t, err)
	sig := make([]byte, protocolv2.ES384SignatureSize)
	const half = protocolv2.ES384SignatureSize / 2
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(sig[half-len(rBytes):half], rBytes)
	copy(sig[protocolv2.ES384SignatureSize-len(sBytes):], sBytes)

	mlSig := make([]byte, protocolv2.MLDSA87SignatureSize)
	err = mldsa87.SignTo(mlPriv, msg, nil, false, mlSig)
	require.NoError(t, err)

	return base64.RawURLEncoding.EncodeToString(sig), base64.RawURLEncoding.EncodeToString(mlSig)
}

// Regression test for https://github.com/ItalyPaleAle/revaulter/issues/23
// The bundle signature is permanently bound to wrappedKeyEpoch=1 (it is created once at signup), but servers that predate the fix echo the user's live epoch in /v2/request/pubkey, which advances on password changes
// Verification must therefore ignore the advertised epoch and reconstruct the payload with the protocol constant
func TestVerifyAndPinAnchorIgnoresAdvertisedEpoch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "trust.json")

	ts, err := loadTrustStore(path)
	require.NoError(t, err)

	esPriv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	jwk, err := protocolv2.ECP384PublicJWKFromECDSA(&esPriv.PublicKey)
	require.NoError(t, err)
	es384Body := jwk.CanonicalBody()

	mlPub, mlPriv, err := mldsa87.GenerateKey(rand.Reader)
	require.NoError(t, err)
	mlPubBytes, err := mlPub.MarshalBinary()
	require.NoError(t, err)
	mlPubB64 := base64.RawURLEncoding.EncodeToString(mlPubBytes)

	ecdhJSON := `{"kty":"EC","crv":"P-256","x":"xxx","y":"yyy"}`
	mlkemB64 := base64.RawURLEncoding.EncodeToString([]byte("mlkem-pub-bytes"))

	sigEs, sigMl := signTestBundle(t, esPriv, mlPriv, &protocolv2.PubkeyBundlePayload{
		UserID:                 "user-1",
		RequestEncEcdhPubkey:   ecdhJSON,
		RequestEncMlkemPubkey:  mlkemB64,
		AnchorEs384Crv:         jwk.Crv,
		AnchorEs384Kty:         jwk.Kty,
		AnchorEs384X:           jwk.X,
		AnchorEs384Y:           jwk.Y,
		AnchorMldsa87PublicKey: mlPubB64,
		WrappedKeyEpoch:        protocolv2.PubkeyBundleWrappedKeyEpoch,
	})

	resp := &v2PubkeyResponse{
		UserID:                 "user-1",
		EcdhP256:               json.RawMessage(ecdhJSON),
		Mlkem768:               mlkemB64,
		AnchorEs384PublicKey:   es384Body,
		AnchorMldsa87PublicKey: mlPubB64,
		// A server that predates the fix reports the user's live epoch here — several rotations past the epoch the bundle was signed over
		WrappedKeyEpoch:              5,
		PubkeyBundleSignatureEs384:   sigEs,
		PubkeyBundleSignatureMldsa87: sigMl,
	}

	pinned, err := verifyAndPinAnchor("https://example.test", resp, ts, func(string) (bool, error) { return true, nil })
	require.NoError(t, err)
	require.True(t, pinned)
}

func TestTrustStorePermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "deep", "trust.json")

	ts := &trustStore{Entries: map[string]trustStoreEntry{}}
	err := saveTrustStore(path, ts)
	require.NoError(t, err)

	info, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm(), "trust store must be 0600")

	loaded, err := loadTrustStore(path)
	require.NoError(t, err)
	require.Equal(t, path, loaded.Path)
}
