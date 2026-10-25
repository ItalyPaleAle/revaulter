package server

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/italypaleale/revaulter/internal/db"
	"github.com/italypaleale/revaulter/internal/protocolv2"
)

// doV2JSON sends a JSON request to the test server and returns the status code and the JSON response decoded into a map
// prepare can add a cookie or headers; pass nil for an unauthenticated request without an Origin header, which is how the native app calls the server
func doV2JSON(t *testing.T, client *http.Client, method string, path string, body any, prepare func(req *http.Request)) (int, map[string]any) {
	t.Helper()

	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		require.NoError(t, err)
		reader = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(t.Context(), method, fmt.Sprintf("https://localhost:%d%s", testServerPort, path), reader)
	require.NoError(t, err)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if prepare != nil {
		prepare(req)
	}

	res, err := client.Do(req)
	require.NoError(t, err)
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		res.Body.Close()
	}()

	var out map[string]any
	_ = json.NewDecoder(res.Body).Decode(&out)
	return res.StatusCode, out
}

func withCookie(cookie *http.Cookie) func(req *http.Request) {
	return func(req *http.Request) {
		req.AddCookie(cookie)
	}
}

func withBearer(token string) func(req *http.Request) {
	return func(req *http.Request) {
		req.Header.Set("Authorization", protocolv2.AuthSchemeBearer+" "+token)
	}
}

func addTestDeviceCredential(t *testing.T, srv *Server, in db.AddCredentialInput) {
	t.Helper()

	in.CredentialType = protocolv2.CredentialTypeDevice
	_, err := db.ExecuteInTransaction(t.Context(), srv.db, 20*time.Second, func(ctx context.Context, tx *db.DbTx) (struct{}, error) {
		return struct{}{}, tx.AuthStore().AddCredential(ctx, in)
	})
	require.NoError(t, err)
}

// testDeviceKeys holds the four private keys of a device credential, standing in for the Secure Enclave
type testDeviceKeys struct {
	credentialID string
	signP256     *ecdsa.PrivateKey
	kaP256       *ecdh.PrivateKey
	signMldsa65  *mldsa.PrivateKey
	kem          *mlkem.DecapsulationKey768
	public       protocolv2.DevicePublicKeys
}

func newTestDeviceKeys(t *testing.T) *testDeviceKeys {
	t.Helper()

	credentialID := make([]byte, protocolv2.DeviceCredentialIDSize)
	_, err := rand.Read(credentialID)
	require.NoError(t, err)

	signP256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	kaP256, err := ecdh.P256().GenerateKey(rand.Reader)
	require.NoError(t, err)
	signMldsa65, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)
	kem, err := mlkem.GenerateKey768()
	require.NoError(t, err)

	signP256Bytes, err := signP256.PublicKey.Bytes()
	require.NoError(t, err)

	return &testDeviceKeys{
		credentialID: base64.RawURLEncoding.EncodeToString(credentialID),
		signP256:     signP256,
		kaP256:       kaP256,
		signMldsa65:  signMldsa65,
		kem:          kem,
		public: protocolv2.DevicePublicKeys{
			SignP256:    base64.RawURLEncoding.EncodeToString(signP256Bytes),
			KaP256:      base64.RawURLEncoding.EncodeToString(kaP256.PublicKey().Bytes()),
			SignMldsa65: base64.RawURLEncoding.EncodeToString(signMldsa65.PublicKey().Bytes()),
			KemMlkem768: base64.RawURLEncoding.EncodeToString(kem.EncapsulationKey().Bytes()),
		},
	}
}

// sign returns the base64url raw r||s P-256 signature and ML-DSA-65 signature of msg, in the formats CryptoKit produces
func (d *testDeviceKeys) sign(t *testing.T, msg []byte) (sigP256 string, sigMldsa65 string) {
	t.Helper()

	digest := sha256.Sum256(msg)
	r, s, err := ecdsa.Sign(rand.Reader, d.signP256, digest[:])
	require.NoError(t, err)
	sig := make([]byte, protocolv2.P256SignatureSize)
	r.FillBytes(sig[:protocolv2.P256SignatureSize/2])
	s.FillBytes(sig[protocolv2.P256SignatureSize/2:])

	mlSig, err := d.signMldsa65.Sign(rand.Reader, msg, nil)
	require.NoError(t, err)

	return base64.RawURLEncoding.EncodeToString(sig), base64.RawURLEncoding.EncodeToString(mlSig)
}

// publicKeyJSON returns the device public keys in the format stored in the credential's public_key column
func (d *testDeviceKeys) publicKeyJSON(t *testing.T) string {
	t.Helper()

	b, err := json.Marshal(d.public)
	require.NoError(t, err)

	return string(b)
}

// addToUser stores the device as a credential of userID
func (d *testDeviceKeys) addToUser(t *testing.T, srv *Server, userID string) {
	t.Helper()

	addTestDeviceCredential(t, srv, db.AddCredentialInput{
		UserID:            userID,
		CredentialID:      d.credentialID,
		DisplayName:       "iPhone",
		PublicKey:         d.publicKeyJSON(t),
		WrappedPrimaryKey: "device-wrapped-primary-key",
		WrappedAnchorKey:  testValidWrappedAnchorEnvelope(t),
	})
}

func TestLoadWebAuthnUserSkipsDeviceCredentials(t *testing.T) {
	setTestConfig(t, "v2-load-webauthn-user.db")
	srv := newTestServer(t, nil, nil, nil)

	_, user := seedV2SessionCookie(t, srv, "user-alice", "Alice")
	addTestDeviceCredential(t, srv, db.AddCredentialInput{
		UserID:       "user-alice",
		CredentialID: "device-1",
		DisplayName:  "iPhone",
		PublicKey:    `{"signP256":"a","kaP256":"b","signMldsa65":"c","kemMlkem768":"d"}`,
	})

	// Two credentials are stored, but only the passkey is a WebAuthn credential
	records, err := srv.db.AuthStore().ListCredentials(t.Context(), "user-alice")
	require.NoError(t, err)
	require.Len(t, records, 2)

	userRecord, err := loadWebAuthnUser(t.Context(), srv.db.AuthStore(), user)
	require.NoError(t, err)
	require.NotNil(t, userRecord)
	require.Len(t, userRecord.WebAuthnCredentials(), 1)
}

func TestServerV2UpdateWrappedKeyRefusedWhilePairing(t *testing.T) {
	setTestConfig(t, "v2-wrapped-key-pairing.db")
	srv := newTestServer(t, nil, nil, nil)
	startTestServer(t, srv)
	client := clientForListener(srv.appListener)

	sessionCookie, _ := seedV2SessionCookie(t, srv, "user-alice", "Alice")
	validAnchor := testValidWrappedAnchorEnvelope(t)
	body := map[string]any{"credentialId": "cred-user-alice", "wrappedPrimaryKey": "new-key-blob", "wrappedAnchorKey": validAnchor, "advanceEpoch": true}

	p, err := db.ExecuteInTransaction(t.Context(), srv.db, 20*time.Second, func(ctx context.Context, tx *db.DbTx) (*db.PairingSession, error) {
		return tx.AuthStore().CreatePairingSession(ctx, "user-alice", "https://vault.example.com", protocolv2.PairingTTL)
	})
	require.NoError(t, err)

	status, out := doV2JSON(t, client, http.MethodPost, "/v2/auth/update-wrapped-key", body, withCookie(sessionCookie))
	require.Equal(t, http.StatusConflict, status)
	require.Contains(t, out["error"], "device is being paired")

	// Once the pairing session ends, the password change goes through
	err = srv.db.AuthStore().CancelPairingSession(t.Context(), p.ID, "user-alice", time.Now())
	require.NoError(t, err)

	status, out = doV2JSON(t, client, http.MethodPost, "/v2/auth/update-wrapped-key", body, withCookie(sessionCookie))
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, true, out["ok"])
}
