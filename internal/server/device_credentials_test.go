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

	"github.com/stretchr/testify/assert"
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

func TestServerV2ListCredentialsTypes(t *testing.T) {
	setTestConfig(t, "v2-list-credential-types.db")
	srv := newTestServer(t, nil, nil, nil)
	startTestServer(t, srv)
	client := clientForListener(srv.appListener)

	cookie, _ := seedV2SessionCookie(t, srv, "user-alice", "Alice")
	device := newTestDeviceKeys(t)
	addTestDeviceCredential(t, srv, db.AddCredentialInput{
		UserID:                      "user-alice",
		CredentialID:                device.credentialID,
		DisplayName:                 "iPhone",
		PublicKey:                   device.publicKeyJSON(t),
		WrappedPrimaryKey:           testDeviceWrappedPrimaryKey(t, device),
		WrappedAnchorKey:            testValidWrappedAnchorEnvelope(t),
		AttestationPayload:          "test-attestation-payload",
		AttestationSignatureEs384:   "test-es384-signature",
		AttestationSignatureMldsa87: "test-mldsa87-signature",
	})

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, fmt.Sprintf("https://localhost:%d/v2/auth/credentials", testServerPort), nil)
	require.NoError(t, err)
	req.AddCookie(cookie)
	res, err := client.Do(req)
	require.NoError(t, err)
	defer res.Body.Close()
	require.Equal(t, http.StatusOK, res.StatusCode)

	var items []map[string]any
	err = json.NewDecoder(res.Body).Decode(&items)
	require.NoError(t, err)
	require.Len(t, items, 2)

	byType := map[string]map[string]any{}
	for _, item := range items {
		typ, _ := item["type"].(string)
		byType[typ] = item
	}

	passkey := byType[protocolv2.CredentialTypePasskey]
	require.NotNil(t, passkey)
	assert.Equal(t, "cred-user-alice", passkey["credentialId"])
	assert.NotContains(t, passkey, "publicKeys")
	assert.NotContains(t, passkey, "attestationPayload")

	dev := byType[protocolv2.CredentialTypeDevice]
	require.NotNil(t, dev)
	assert.Equal(t, device.credentialID, dev["credentialId"])
	assert.Equal(t, "iPhone", dev["displayName"])
	assert.Equal(t, "test-attestation-payload", dev["attestationPayload"])
	assert.Equal(t, "test-es384-signature", dev["attestationSignatureEs384"])
	assert.Equal(t, "test-mldsa87-signature", dev["attestationSignatureMldsa87"])
	assert.Equal(t, map[string]any{
		"signP256":    device.public.SignP256,
		"kaP256":      device.public.KaP256,
		"signMldsa65": device.public.SignMldsa65,
		"kemMlkem768": device.public.KemMlkem768,
	}, dev["publicKeys"])

	// The wrappers are never listed
	assert.NotContains(t, dev, "wrappedPrimaryKey")
	assert.NotContains(t, dev, "wrappedAnchorKey")
}

func TestServerV2UpdateWrappedKeyBatch(t *testing.T) {
	setTestConfig(t, "v2-wrapped-key-batch.db")
	srv := newTestServer(t, nil, nil, nil)
	startTestServer(t, srv)
	client := clientForListener(srv.appListener)

	cookie, _ := seedV2SessionCookie(t, srv, "user-alice", "Alice")
	device1 := newTestDeviceKeys(t)
	device1.addToUser(t, srv, "user-alice")
	device2 := newTestDeviceKeys(t)
	device2.addToUser(t, srv, "user-alice")
	anchorKey := testValidWrappedAnchorEnvelope(t)

	update := func(t *testing.T, body map[string]any) (int, map[string]any) {
		t.Helper()
		return doV2JSON(t, client, http.MethodPost, "/v2/auth/update-wrapped-key", body, withCookie(cookie))
	}
	userEpoch := func(t *testing.T) int64 {
		t.Helper()
		user, err := srv.db.AuthStore().GetUserByID(t.Context(), "user-alice")
		require.NoError(t, err)
		require.NotNil(t, user)
		return user.WrappedKeyEpoch
	}
	wrapper := func(t *testing.T, credentialID string) (string, int64) {
		t.Helper()
		cred, err := srv.db.AuthStore().GetCredentialForUser(t.Context(), "user-alice", credentialID)
		require.NoError(t, err)
		require.NotNil(t, cred)
		return cred.WrappedPrimaryKey, cred.WrappedKeyEpoch
	}

	t.Run("re-wraps every credential with the epoch advance", func(t *testing.T) {
		device1Key := testDeviceWrappedPrimaryKey(t, device1)
		device2Key := testDeviceWrappedPrimaryKey(t, device2)
		status, out := update(t, map[string]any{
			"advanceEpoch": true,
			"updates": []map[string]any{
				{"credentialId": "cred-user-alice", "wrappedPrimaryKey": "new-passkey-blob", "wrappedAnchorKey": anchorKey},
				{"credentialId": device1.credentialID, "wrappedPrimaryKey": device1Key, "wrappedAnchorKey": anchorKey},
				{"credentialId": device2.credentialID, "wrappedPrimaryKey": device2Key, "wrappedAnchorKey": anchorKey},
			},
		})
		require.Equal(t, http.StatusOK, status, out)

		require.Equal(t, int64(2), userEpoch(t))
		for id, want := range map[string]string{"cred-user-alice": "new-passkey-blob", device1.credentialID: device1Key, device2.credentialID: device2Key} {
			got, epoch := wrapper(t, id)
			assert.Equal(t, want, got, id)
			assert.Equal(t, int64(2), epoch, id)
		}

		rows := auditByType(t, srv, "user-alice", db.AuditAuthWrappedKeyUpdate)
		assert.Len(t, rows, 3)
	})

	t.Run("an unknown credential rolls back the whole batch", func(t *testing.T) {
		before, _ := wrapper(t, device1.credentialID)

		status, _ := update(t, map[string]any{
			"advanceEpoch": true,
			"updates": []map[string]any{
				{"credentialId": device1.credentialID, "wrappedPrimaryKey": testDeviceWrappedPrimaryKey(t, device1), "wrappedAnchorKey": anchorKey},
				{"credentialId": "cred-unknown", "wrappedPrimaryKey": "blob", "wrappedAnchorKey": anchorKey},
			},
		})
		require.Equal(t, http.StatusNotFound, status)

		require.Equal(t, int64(2), userEpoch(t))
		after, _ := wrapper(t, device1.credentialID)
		assert.Equal(t, before, after)
	})

	t.Run("a device needs a device envelope", func(t *testing.T) {
		before, _ := wrapper(t, "cred-user-alice")

		status, out := update(t, map[string]any{
			"advanceEpoch": true,
			"updates": []map[string]any{
				{"credentialId": "cred-user-alice", "wrappedPrimaryKey": "another-passkey-blob", "wrappedAnchorKey": anchorKey},
				{"credentialId": device2.credentialID, "wrappedPrimaryKey": "not-an-envelope", "wrappedAnchorKey": anchorKey},
			},
		})
		require.Equal(t, http.StatusBadRequest, status)
		assert.Contains(t, out["error"], device2.credentialID)

		require.Equal(t, int64(2), userEpoch(t))
		after, _ := wrapper(t, "cred-user-alice")
		assert.Equal(t, before, after)

		// The single-credential form applies the same check
		status, _ = update(t, map[string]any{"credentialId": device2.credentialID, "wrappedPrimaryKey": "not-an-envelope", "wrappedAnchorKey": anchorKey})
		require.Equal(t, http.StatusBadRequest, status)
	})

	t.Run("invalid batches", func(t *testing.T) {
		valid := map[string]any{"credentialId": device1.credentialID, "wrappedPrimaryKey": testDeviceWrappedPrimaryKey(t, device1), "wrappedAnchorKey": anchorKey}
		tooMany := make([]map[string]any, maxWrappedKeyUpdates+1)
		for i := range tooMany {
			tooMany[i] = map[string]any{"credentialId": fmt.Sprintf("cred-%d", i), "wrappedPrimaryKey": "blob"}
		}

		cases := map[string]map[string]any{
			"combined with credentialId": {"credentialId": "cred-user-alice", "updates": []map[string]any{valid}},
			"duplicate credential":       {"updates": []map[string]any{valid, valid}},
			"missing credentialId":       {"updates": []map[string]any{{"wrappedPrimaryKey": "blob"}}},
			"too many updates":           {"updates": tooMany},
			"invalid anchor envelope":    {"updates": []map[string]any{{"credentialId": device1.credentialID, "wrappedPrimaryKey": "blob", "wrappedAnchorKey": "nope"}}},
		}
		for name, body := range cases {
			t.Run(name, func(t *testing.T) {
				status, _ := update(t, body)
				require.Equal(t, http.StatusBadRequest, status)
			})
		}
	})
}

func TestServerV2DeleteLastPasskey(t *testing.T) {
	setTestConfig(t, "v2-delete-last-passkey.db")
	srv := newTestServer(t, nil, nil, nil)
	startTestServer(t, srv)
	client := clientForListener(srv.appListener)

	cookie, _ := seedV2SessionCookie(t, srv, "user-alice", "Alice")
	device := newTestDeviceKeys(t)
	device.addToUser(t, srv, "user-alice")

	records, err := srv.db.AuthStore().ListCredentials(t.Context(), "user-alice")
	require.NoError(t, err)
	var passkeyID, deviceID string
	for _, rec := range records {
		switch rec.CredentialType {
		case protocolv2.CredentialTypePasskey:
			passkeyID = rec.ID
		case protocolv2.CredentialTypeDevice:
			deviceID = rec.ID
		}
	}
	require.NotEmpty(t, passkeyID)
	require.NotEmpty(t, deviceID)

	deleteCredential := func(t *testing.T, id string) (int, map[string]any) {
		t.Helper()
		return doV2JSON(t, client, http.MethodPost, "/v2/auth/credentials/delete", map[string]any{"id": id}, withCookie(cookie))
	}

	// The only passkey can't go while a device remains
	status, out := deleteCredential(t, passkeyID)
	require.Equal(t, http.StatusConflict, status)
	assert.Equal(t, "An account must keep at least one passkey", out["error"])

	// The device can
	status, out = deleteCredential(t, deviceID)
	require.Equal(t, http.StatusOK, status, out)

	// Now the passkey is the last credential
	status, out = deleteCredential(t, passkeyID)
	require.Equal(t, http.StatusConflict, status)
	assert.Equal(t, "Cannot delete the last credential", out["error"])
}
