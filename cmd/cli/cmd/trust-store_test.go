//go:build unit

package cmd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	"github.com/stretchr/testify/require"

	"github.com/italypaleale/revaulter/pkg/protocolv2"
)

func newTestAnchorPubkeys(t *testing.T) (*ecdsa.PublicKey, json.RawMessage, []byte, string) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	jwk, err := protocolv2.ECP384PublicJWKFromECDSA(&priv.PublicKey)
	require.NoError(t, err)
	jwkBytes, err := json.Marshal(jwk)
	require.NoError(t, err)

	mlPub, _, err := mldsa87.GenerateKey(rand.Reader)
	require.NoError(t, err)
	mlPubBytes, err := mlPub.MarshalBinary()
	require.NoError(t, err)
	mlPubB64 := base64.RawURLEncoding.EncodeToString(mlPubBytes)

	return &priv.PublicKey, jwkBytes, mlPubBytes, mlPubB64
}

func TestTrustStorePinAndReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "trust.json")

	ts, err := loadTrustStore(path)
	require.NoError(t, err)
	require.Empty(t, ts.Entries)

	es384Pub, es384Raw, mlPubBytes, mlPubB64 := newTestAnchorPubkeys(t)

	// First contact — accept.
	pinned, err := ts.checkOrPinAnchor("https://example.test", "req-1", es384Pub, es384Raw, mlPubB64, mlPubBytes,
		func(fp string) (bool, error) {
			require.NotEmpty(t, fp)
			return true, nil
		})
	require.NoError(t, err)
	require.True(t, pinned)

	err = saveTrustStore(path, ts)
	require.NoError(t, err)

	// Reload — subsequent match must not re-prompt.
	ts2, err := loadTrustStore(path)
	require.NoError(t, err)
	prompted := false
	pinned, err = ts2.checkOrPinAnchor("https://example.test", "req-1", es384Pub, es384Raw, mlPubB64, mlPubBytes,
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

	_, err = ts.checkOrPinAnchor("https://example.test", "req-1", es384PubA, es384RawA, mlPubB64A, mlPubBytesA,
		func(string) (bool, error) { return true, nil })
	require.NoError(t, err)
	require.NoError(t, saveTrustStore(path, ts))

	// Mismatch in ML-DSA-87 half must be caught.
	ts2, err := loadTrustStore(path)
	require.NoError(t, err)
	_, err = ts2.checkOrPinAnchor("https://example.test", "req-1", es384PubA, es384RawA, mlPubB64B, mlPubBytesB,
		func(string) (bool, error) { return true, nil })
	require.Error(t, err)

	// Mismatch in ES384 half must also be caught.
	ts3, err := loadTrustStore(path)
	require.NoError(t, err)
	_, err = ts3.checkOrPinAnchor("https://example.test", "req-1", es384PubB, es384RawB, mlPubB64A, mlPubBytesA,
		func(string) (bool, error) { return true, nil })
	require.Error(t, err)
}

func TestTrustStoreFailsClosedOnNoConfirm(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "trust.json")

	ts, err := loadTrustStore(path)
	require.NoError(t, err)

	es384Pub, es384Raw, mlPubBytes, mlPubB64 := newTestAnchorPubkeys(t)

	_, err = ts.checkOrPinAnchor("https://example.test", "req-1", es384Pub, es384Raw, mlPubB64, mlPubBytes, nil)
	require.Error(t, err, "first contact with nil confirmer must refuse")
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
}
