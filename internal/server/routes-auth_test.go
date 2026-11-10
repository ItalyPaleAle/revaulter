package server

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/mlkem"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/italypaleale/revaulter/internal/db"
	"github.com/italypaleale/revaulter/internal/protocolv2"
)

// TestServerV2SignupFlow runs a full signup over HTTP: the user stays in the revaulter.signup actor until finalize-signup creates it in the database
func TestServerV2SignupFlow(t *testing.T) {
	setTestConfig(t, "v2-signup-flow.db", map[string]any{
		"baseUrl":         testWebAuthnOrigin,
		"webauthnRpId":    testWebAuthnRPID,
		"webauthnOrigins": []string{testWebAuthnOrigin},
	})

	srv := newTestServer(t, nil, nil, nil)
	startTestServer(t, srv)
	client := clientForListener(srv.appListener)
	pk := newTestPasskey(t, webauthncose.AlgES256)

	// Register the passkey
	res := doSignupTestRequest(t, client, http.MethodPost, "/v2/auth/register/begin", map[string]any{"displayName": "Carol"}, nil)
	require.Equal(t, http.StatusOK, res.StatusCode)
	signupID := stringField(t, res.Body, "challengeId")
	userHandle, err := base64.RawURLEncoding.DecodeString(signupID)
	require.NoError(t, err)

	registerBody := map[string]any{
		"challengeId": signupID,
		"credential":  pk.attestationResponse(t, stringField(t, res.Body, "challenge")),
	}
	res = doSignupTestRequest(t, client, http.MethodPost, "/v2/auth/register/finish", registerBody, nil)
	require.Equal(t, http.StatusOK, res.StatusCode, "register/finish failed: %v", res.Body)
	session, _ := res.Body["session"].(map[string]any)
	require.NotNil(t, session)
	userID := stringField(t, session, "userId")
	assert.Equal(t, "Carol", session["displayName"])
	assert.Empty(t, session["requestKey"])
	registerCookie := sessionCookieFromResponse(t, res)

	// The registration challenge can be used once only
	res = doSignupTestRequest(t, client, http.MethodPost, "/v2/auth/register/finish", registerBody, nil)
	require.Equal(t, http.StatusConflict, res.StatusCode)

	// The user isn't in the database until the signup is finalized, and the session isn't ready
	user, err := srv.db.AuthStore().GetUserByID(t.Context(), userID)
	require.NoError(t, err)
	require.Nil(t, user)
	res = doSignupTestRequest(t, client, http.MethodGet, "/v2/auth/session", nil, registerCookie)
	require.Equal(t, http.StatusForbidden, res.StatusCode)

	// Sign in with the passkey before the signup is finalized, as the browser does to derive the wrapping key
	loginBody := signupTestLogin(t, client, pk, userHandle)
	res = doSignupTestRequest(t, client, http.MethodPost, "/v2/auth/login/finish", loginBody, nil)
	require.Equal(t, http.StatusOK, res.StatusCode, "login/finish failed: %v", res.Body)
	assert.Equal(t, true, res.Body["authenticated"])
	assert.Empty(t, res.Body["wrappedPrimaryKey"])
	session, _ = res.Body["session"].(map[string]any)
	require.NotNil(t, session)
	assert.Equal(t, userID, session["userId"])
	loginCookie := sessionCookieFromResponse(t, res)

	// The login challenge can be used once only
	res = doSignupTestRequest(t, client, http.MethodPost, "/v2/auth/login/finish", loginBody, nil)
	require.Equal(t, http.StatusConflict, res.StatusCode)

	// Finalize the signup
	credentialID := base64.RawURLEncoding.EncodeToString(pk.credentialID)
	credentialPublicKeyHash, err := protocolv2.CredentialPublicKeyHash(pk.coseKey)
	require.NoError(t, err)
	finalizeBody := newSignupTestFinalizeBody(t, userID, credentialID, credentialPublicKeyHash)
	res = doSignupTestRequest(t, client, http.MethodPost, "/v2/auth/finalize-signup", finalizeBody, loginCookie)
	require.Equal(t, http.StatusOK, res.StatusCode, "finalize-signup failed: %v", res.Body)
	readyCookie := sessionCookieFromResponse(t, res)

	user, err = srv.db.AuthStore().GetUserByID(t.Context(), userID)
	require.NoError(t, err)
	require.NotNil(t, user)
	assert.True(t, user.Ready)
	assert.Equal(t, "Carol", user.DisplayName)
	assert.Equal(t, signupID, user.WebAuthnUserID)

	creds, err := srv.db.AuthStore().ListCredentials(t.Context(), userID)
	require.NoError(t, err)
	require.Len(t, creds, 1)
	assert.Equal(t, credentialID, creds[0].CredentialID)
	assert.EqualValues(t, 1, creds[0].SignCount, "the sign count from the sign-in before finalize must be kept")

	for _, eventType := range []db.EventType{db.AuditAuthRegisterFinish, db.AuditAuthLoginFinish, db.AuditAuthFinalizeSignup} {
		events, _, err := srv.db.AuditStore().List(t.Context(), db.AuditFilter{UserID: userID, EventType: eventType}, 10, "")
		require.NoError(t, err)
		assert.Len(t, events, 1, "audit events of type %s", eventType)
	}

	// The ready session works, and the signup can't be finalized twice
	res = doSignupTestRequest(t, client, http.MethodGet, "/v2/auth/session", nil, readyCookie)
	require.Equal(t, http.StatusOK, res.StatusCode)
	res = doSignupTestRequest(t, client, http.MethodPost, "/v2/auth/finalize-signup", newSignupTestFinalizeBody(t, userID, credentialID, credentialPublicKeyHash), loginCookie)
	require.Equal(t, http.StatusConflict, res.StatusCode)

	// Signing in now uses the user in the database, which returns the wrapped primary key
	res = doSignupTestRequest(t, client, http.MethodPost, "/v2/auth/login/finish", signupTestLogin(t, client, pk, userHandle), nil)
	require.Equal(t, http.StatusOK, res.StatusCode, "login/finish failed: %v", res.Body)
	assert.Equal(t, finalizeBody["wrappedPrimaryKey"], res.Body["wrappedPrimaryKey"])
}

// signupTestLogin begins a sign-in, and returns the body for login/finish with the passkey's assertion
func signupTestLogin(t *testing.T, client *http.Client, pk *testPasskey, userHandle []byte) map[string]any {
	t.Helper()

	res := doSignupTestRequest(t, client, http.MethodPost, "/v2/auth/login/begin", nil, nil)
	require.Equal(t, http.StatusOK, res.StatusCode)

	return map[string]any{
		"challengeId": stringField(t, res.Body, "challengeId"),
		"credential":  pk.assertionResponse(t, stringField(t, res.Body, "challenge"), userHandle),
	}
}

// newSignupTestFinalizeBody returns a finalize-signup request with freshly generated keys, signed by a new anchor
func newSignupTestFinalizeBody(t *testing.T, userID string, credentialID string, credentialPublicKeyHash string) map[string]any {
	t.Helper()

	// Transport keys
	ecdhPriv, err := ecdh.P256().GenerateKey(rand.Reader)
	require.NoError(t, err)
	ecdhJWK, err := protocolv2.ECP256PublicJWKFromECDH(ecdhPriv.PublicKey())
	require.NoError(t, err)
	ecdhJWKJSON, err := json.Marshal(ecdhJWK)
	require.NoError(t, err)
	mlkemKey, err := mlkem.GenerateKey768()
	require.NoError(t, err)
	mlkemPub := base64.RawURLEncoding.EncodeToString(mlkemKey.EncapsulationKey().Bytes())

	// Anchor
	esPriv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	mlPriv, err := mldsa.GenerateKey(mldsa.MLDSA87())
	require.NoError(t, err)
	es384JWK, err := protocolv2.ECP384PublicJWKFromECDSA(&esPriv.PublicKey)
	require.NoError(t, err)
	anchor := &testAnchorKeyPair{
		Es384Priv:        esPriv,
		Mldsa87Priv:      mlPriv,
		Mldsa87Pub:       mlPriv.PublicKey(),
		Mldsa87PubBytes:  mlPriv.PublicKey().Bytes(),
		Es384JWKBody:     es384JWK.CanonicalBody(),
		Mldsa87PubBase64: base64.RawURLEncoding.EncodeToString(mlPriv.PublicKey().Bytes()),
	}

	bundleSigEs, bundleSigMl := signPubkeyBundleV2(t, anchor, &protocolv2.PubkeyBundlePayloadV2{
		UserID:                 userID,
		RequestEncEcdhPubkey:   string(ecdhJWKJSON),
		RequestEncMlkemPubkey:  mlkemPub,
		AnchorEs384Crv:         es384JWK.Crv,
		AnchorEs384Kty:         es384JWK.Kty,
		AnchorEs384X:           es384JWK.X,
		AnchorEs384Y:           es384JWK.Y,
		AnchorMldsa87PublicKey: anchor.Mldsa87PubBase64,
		V:                      protocolv2.PubkeyBundleVersion2,
	})

	attestation := &protocolv2.AttestationPayload{
		UserID:                  userID,
		CredentialID:            credentialID,
		CredentialPublicKeyHash: credentialPublicKeyHash,
		WrappedKeyEpoch:         1,
		CreatedAt:               time.Now().Unix(),
	}
	attestSigEs, attestSigMl := signHybridMessage(t, anchor, protocolv2.CanonicalAttestationMessage(attestation))

	return map[string]any{
		"requestEncEcdhPubkey":         json.RawMessage(ecdhJWKJSON),
		"requestEncMlkemPubkey":        mlkemPub,
		"wrappedPrimaryKey":            "test-wrapped-primary-key",
		"anchorEs384PublicKey":         anchor.Es384JWKBody,
		"anchorMldsa87PublicKey":       anchor.Mldsa87PubBase64,
		"pubkeyBundleSignatureEs384":   bundleSigEs,
		"pubkeyBundleSignatureMldsa87": bundleSigMl,
		"pubkeyBundleVersion":          protocolv2.PubkeyBundleVersion2,
		"wrappedAnchorKey":             testValidWrappedAnchorEnvelope(t),
		"attestationPayload":           attestation.CanonicalBody(),
		"attestationSignatureEs384":    attestSigEs,
		"attestationSignatureMldsa87":  attestSigMl,
	}
}

// signupTestResponse is a response from the test server, with its body decoded as a JSON object
type signupTestResponse struct {
	StatusCode int
	Cookies    []*http.Cookie
	Body       map[string]any
}

// doSignupTestRequest sends a request to the test server
func doSignupTestRequest(t *testing.T, client *http.Client, method string, path string, body any, cookie *http.Cookie) signupTestResponse {
	t.Helper()

	var reqBody io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		require.NoError(t, err)
		reqBody = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(t.Context(), method, fmt.Sprintf("https://localhost:%d%s", testServerPort, path), reqBody)
	require.NoError(t, err)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}

	res, err := client.Do(req)
	require.NoError(t, err)
	defer res.Body.Close()

	out := signupTestResponse{
		StatusCode: res.StatusCode,
		Cookies:    res.Cookies(),
	}
	_ = json.NewDecoder(res.Body).Decode(&out.Body)

	return out
}

// stringField returns a string field of a JSON object
func stringField(t *testing.T, obj map[string]any, key string) string {
	t.Helper()

	val, ok := obj[key].(string)
	require.True(t, ok, "field '%s' is not a string", key)

	return val
}

// sessionCookieFromResponse returns the session cookie set by a response
func sessionCookieFromResponse(t *testing.T, res signupTestResponse) *http.Cookie {
	t.Helper()

	for _, c := range res.Cookies {
		if c.Name == sessionCookieNameSecure && c.Value != "" {
			return c
		}
	}

	t.Fatal("the response didn't set the session cookie")
	return nil
}
