package server

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/italypaleale/revaulter/internal/db"
	"github.com/italypaleale/revaulter/internal/protocolv2"
	"github.com/italypaleale/revaulter/internal/requestjwt"
)

const (
	testOIDCAudience       = "https://revaulter.example.com"
	testOIDCSubject        = "repo:example/app:environment:release"
	testOIDCSubjectPattern = "repo:example/app:environment:*"
)

// doRequestCredentialJSON sends an HTTP request to /v2/request/<suffix> with the given Authorization header, and the user ID in the X-Revaulter-User header when set
// The helper drains and closes the response body before returning
func doRequestCredentialJSON(t *testing.T, client *http.Client, method, suffix, authorization, userID string, body any) (*http.Response, map[string]any) {
	t.Helper()

	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		require.NoError(t, err)
		reader = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(t.Context(), method, fmt.Sprintf("https://localhost:%d/v2/request/%s", testServerPort, suffix), reader)
	require.NoError(t, err)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	if userID != "" {
		req.Header.Set(protocolv2.UserIDHeader, userID)
	}

	res, err := client.Do(req)
	require.NoError(t, err)
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		res.Body.Close()
	}()

	var out map[string]any
	_ = json.NewDecoder(res.Body).Decode(&out)
	return res, out
}

// doSessionPostJSON sends a POST request to path, authenticated with the session cookie
func doSessionPostJSON(t *testing.T, client *http.Client, path string, cookie *http.Cookie, body any) (*http.Response, map[string]any) {
	t.Helper()

	b, err := json.Marshal(body)
	require.NoError(t, err)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, fmt.Sprintf("https://localhost:%d%s", testServerPort, path), bytes.NewReader(b))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)

	res, err := client.Do(req)
	require.NoError(t, err)
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		res.Body.Close()
	}()

	var out map[string]any
	_ = json.NewDecoder(res.Body).Decode(&out)
	return res, out
}

// newOIDCTestServer starts a server whose JWT verifier trusts the TLS certificate of the test issuer
func newOIDCTestServer(t *testing.T, iss *requestjwt.TestIssuer) (*Server, *http.Client) {
	t.Helper()

	setTestConfig(t, "v2-oidc.db")
	srv := newTestServer(t, nil, nil, nil)
	srv.requestJWT = requestjwt.NewVerifier(requestjwt.NewVerifierOptions{
		HTTPClient: iss.HTTPClient(),
	})
	startTestServer(t, srv)

	return srv, clientForListener(srv.appListener)
}

// enableOIDCForUser enables OIDC tokens for the user, trusting the issuer for the given subject pattern
// The request key stays enabled
func enableOIDCForUser(t *testing.T, srv *Server, userID string, iss *requestjwt.TestIssuer, subject string) {
	t.Helper()

	_, err := db.ExecuteInTransaction(t.Context(), srv.db, 30*time.Second, func(ctx context.Context, tx *db.DbTx) (struct{}, error) {
		as := tx.AuthStore()
		_, _, err := as.AddRequestOIDCIssuer(ctx, userID, db.AddRequestOIDCIssuerInput{
			Issuer:   iss.URL,
			Audience: testOIDCAudience,
			Subject:  subject,
		})
		if err != nil {
			return struct{}{}, err
		}

		return struct{}{}, as.UpdateRequestAuthMethods(ctx, userID, db.RequestAuthMethods{RequestKey: true, OIDC: true})
	})
	require.NoError(t, err)
}

func newTestCreateBody(t *testing.T) map[string]any {
	t.Helper()

	clientPriv, err := ecdh.P256().GenerateKey(rand.Reader)
	require.NoError(t, err)
	clientJWK, err := protocolv2.ECP256PublicJWKFromECDH(clientPriv.PublicKey())
	require.NoError(t, err)

	return newV2CreateRequestBody("disk-key", "A256GCM", clientJWK)
}

func TestServerRequestOIDCAuthentication(t *testing.T) {
	iss := requestjwt.NewTestIssuer(t)
	srv, client := newOIDCTestServer(t, iss)

	_, alice := seedV2SessionCookie(t, srv, "user-alice", "Alice")
	_, bob := seedV2SessionCookie(t, srv, "user-bob", "Bob")

	// Both users trust the same issuer, audience, and subject: the X-Revaulter-User header picks the user
	const subject = "repo:example/app:ref:refs/tags/v1.0.0"
	enableOIDCForUser(t, srv, alice.ID, iss, "repo:example/app:ref:refs/tags/*")
	enableOIDCForUser(t, srv, bob.ID, iss, "repo:example/app:ref:refs/tags/*")

	t.Run("creates a request for the user in the header", func(t *testing.T) {
		token := iss.Token(subject, testOIDCAudience, func(b *jwt.Builder) {
			b.JwtID("run-42")
		})

		//nolint:bodyclose
		res, body := doRequestCredentialJSON(t, client, http.MethodPost, "encrypt", "Bearer "+token, bob.ID, newTestCreateBody(t))
		require.Equal(t, http.StatusAccepted, res.StatusCode, body)
		state, _ := body["state"].(string)
		require.NotEmpty(t, state)
		resultToken, _ := body["resultToken"].(string)
		require.True(t, strings.HasPrefix(resultToken, resultTokenPrefix))

		rec, err := srv.db.RequestStore().GetRequest(t.Context(), state)
		require.NoError(t, err)
		require.Equal(t, bob.ID, rec.UserID)

		// The audit log records the method and the verified claims
		events, _, err := srv.db.AuditStore().List(t.Context(), db.AuditFilter{UserID: bob.ID, EventType: db.AuditRequestCreate}, 10, "")
		require.NoError(t, err)
		require.Len(t, events, 1)
		require.Equal(t, db.AuditAuthMethodRequestOIDC, events[0].AuthMethod)
		var metadata map[string]any
		require.NoError(t, json.Unmarshal(events[0].Metadata, &metadata))
		assert.Equal(t, iss.URL, metadata["jwtIssuer"])
		assert.Equal(t, subject, metadata["jwtSubject"])
		assert.Equal(t, "run-42", metadata["jwtId"])
	})

	t.Run("fetches the pubkey of the user in the header", func(t *testing.T) {
		//nolint:bodyclose
		res, body := doRequestCredentialJSON(t, client, http.MethodGet, "pubkey", "Bearer "+iss.Token(subject, testOIDCAudience), alice.ID, nil)
		require.Equal(t, http.StatusOK, res.StatusCode, body)
		require.Equal(t, alice.ID, body["userId"])
	})

	rejected := []struct {
		name   string
		token  func() string
		userID string
	}{
		{
			name:   "missing user header",
			token:  func() string { return iss.Token(subject, testOIDCAudience) },
			userID: "",
		},
		{
			name:   "unknown user",
			token:  func() string { return iss.Token(subject, testOIDCAudience) },
			userID: "user-missing",
		},
		{
			name:   "subject not trusted",
			token:  func() string { return iss.Token("repo:example/app:ref:refs/heads/main", testOIDCAudience) },
			userID: alice.ID,
		},
		{
			name:   "wrong audience",
			token:  func() string { return iss.Token(subject, "https://other.example.com") },
			userID: alice.ID,
		},
		{
			name: "expired",
			token: func() string {
				return iss.Token(subject, testOIDCAudience, func(b *jwt.Builder) {
					b.IssuedAt(time.Now().Add(-time.Hour))
					b.Expiration(time.Now().Add(-10 * time.Minute))
				})
			},
			userID: alice.ID,
		},
	}
	for _, tt := range rejected {
		t.Run("rejects "+tt.name, func(t *testing.T) {
			//nolint:bodyclose
			res, body := doRequestCredentialJSON(t, client, http.MethodPost, "encrypt", "Bearer "+tt.token(), tt.userID, newTestCreateBody(t))
			require.Equal(t, http.StatusUnauthorized, res.StatusCode, body)
		})
	}

	t.Run("accepts the request key too when both methods are enabled", func(t *testing.T) {
		//nolint:bodyclose
		res, body := doRequestCredentialJSON(t, client, http.MethodPost, "encrypt", "RequestKey "+alice.RequestKey, "", newTestCreateBody(t))
		require.Equal(t, http.StatusAccepted, res.StatusCode, body)
	})

	t.Run("rejects the request key when it's disabled", func(t *testing.T) {
		err := srv.db.AuthStore().UpdateRequestAuthMethods(t.Context(), alice.ID, db.RequestAuthMethods{OIDC: true})
		require.NoError(t, err)

		//nolint:bodyclose
		res, body := doRequestCredentialJSON(t, client, http.MethodPost, "encrypt", "RequestKey "+alice.RequestKey, "", newTestCreateBody(t))
		require.Equal(t, http.StatusForbidden, res.StatusCode, body)
		require.Contains(t, body["error"], "disabled")

		// OIDC tokens keep working
		//nolint:bodyclose
		res, body = doRequestCredentialJSON(t, client, http.MethodPost, "encrypt", "Bearer "+iss.Token(subject, testOIDCAudience), alice.ID, newTestCreateBody(t))
		require.Equal(t, http.StatusAccepted, res.StatusCode, body)
	})

	t.Run("rejects a JWT when OIDC is disabled", func(t *testing.T) {
		_, carol := seedV2SessionCookie(t, srv, "user-carol", "Carol")
		_, err := db.ExecuteInTransaction(t.Context(), srv.db, 30*time.Second, func(ctx context.Context, tx *db.DbTx) (struct{}, error) {
			_, _, err := tx.AuthStore().AddRequestOIDCIssuer(ctx, carol.ID, db.AddRequestOIDCIssuerInput{
				Issuer:   iss.URL,
				Audience: testOIDCAudience,
				Subject:  subject,
			})
			return struct{}{}, err
		})
		require.NoError(t, err)

		//nolint:bodyclose
		res, body := doRequestCredentialJSON(t, client, http.MethodPost, "encrypt", "Bearer "+iss.Token(subject, testOIDCAudience), carol.ID, newTestCreateBody(t))
		require.Equal(t, http.StatusUnauthorized, res.StatusCode, body)
	})
}

func TestServerRequestOIDCLongClaims(t *testing.T) {
	iss := requestjwt.NewTestIssuer(t)
	srv, client := newOIDCTestServer(t, iss)

	_, alice := seedV2SessionCookie(t, srv, "user-alice", "Alice")
	enableOIDCForUser(t, srv, alice.ID, iss, "repo:example/app:*")

	// Claims this long would push the audit metadata over its size limit if they weren't truncated
	subject := "repo:example/app:" + strings.Repeat("s", 3000)
	token := iss.Token(subject, testOIDCAudience, func(b *jwt.Builder) {
		b.JwtID(strings.Repeat("j", 2000))
	})

	//nolint:bodyclose
	res, body := doRequestCredentialJSON(t, client, http.MethodPost, "encrypt", "Bearer "+token, alice.ID, newTestCreateBody(t))
	require.Equal(t, http.StatusAccepted, res.StatusCode, body)

	events, _, err := srv.db.AuditStore().List(t.Context(), db.AuditFilter{UserID: alice.ID, EventType: db.AuditRequestCreate}, 10, "")
	require.NoError(t, err)
	require.Len(t, events, 1)
	var metadata map[string]any
	require.NoError(t, json.Unmarshal(events[0].Metadata, &metadata))
	jwtSubject, _ := metadata["jwtSubject"].(string)
	require.True(t, strings.HasPrefix(subject, strings.TrimSuffix(jwtSubject, "…")))
	require.Less(t, len(jwtSubject), 300)
	jwtID, _ := metadata["jwtId"].(string)
	require.Less(t, len(jwtID), 300)
}

func TestServerRequestOIDCDatabaseError(t *testing.T) {
	iss := requestjwt.NewTestIssuer(t)
	srv, client := newOIDCTestServer(t, iss)

	_, alice := seedV2SessionCookie(t, srv, "user-alice", "Alice")
	enableOIDCForUser(t, srv, alice.ID, iss, testOIDCSubjectPattern)

	// When the user can't be loaded, the response is an internal error, not a claim that the token is invalid
	require.NoError(t, srv.db.Close(t.Context()))

	//nolint:bodyclose
	res, body := doRequestCredentialJSON(t, client, http.MethodGet, "pubkey", "Bearer "+iss.Token(testOIDCSubject, testOIDCAudience), alice.ID, nil)
	require.Equal(t, http.StatusInternalServerError, res.StatusCode, body)
}

func TestServerRequestResultToken(t *testing.T) {
	iss := requestjwt.NewTestIssuer(t)
	srv, client := newOIDCTestServer(t, iss)

	sessionCookie, alice := seedV2SessionCookie(t, srv, "user-alice", "Alice")
	_, bob := seedV2SessionCookie(t, srv, "user-bob", "Bob")

	const subject = "repo:example/app:environment:release"
	enableOIDCForUser(t, srv, alice.ID, iss, subject)

	//nolint:bodyclose
	res, body := doRequestCredentialJSON(t, client, http.MethodPost, "encrypt", "Bearer "+iss.Token(subject, testOIDCAudience), alice.ID, newTestCreateBody(t))
	require.Equal(t, http.StatusAccepted, res.StatusCode, body)
	state, _ := body["state"].(string)
	resultToken, _ := body["resultToken"].(string)
	require.NotEmpty(t, resultToken)

	// Create a second request, for another user, to check that result tokens are bound to their request
	//nolint:bodyclose
	res, body = doRequestCredentialJSON(t, client, http.MethodPost, "encrypt", "RequestKey "+bob.RequestKey, "", newTestCreateBody(t))
	require.Equal(t, http.StatusAccepted, res.StatusCode, body)
	bobState, _ := body["state"].(string)
	bobResultToken, _ := body["resultToken"].(string)

	// Once the JWT has expired, it can't be used to poll for the result anymore, but the result token can
	expired := iss.Token(subject, testOIDCAudience, func(b *jwt.Builder) {
		b.IssuedAt(time.Now().Add(-time.Hour))
		b.Expiration(time.Now().Add(-10 * time.Minute))
	})
	//nolint:bodyclose
	res, body = doRequestCredentialJSON(t, client, http.MethodGet, "result/"+state, "Bearer "+expired, alice.ID, nil)
	require.Equal(t, http.StatusUnauthorized, res.StatusCode, body)

	// A result token only works for its own request
	//nolint:bodyclose
	res, body = doRequestCredentialJSON(t, client, http.MethodGet, "result/"+bobState, "ResultToken "+resultToken, "", nil)
	require.Equal(t, http.StatusNotFound, res.StatusCode, body)
	//nolint:bodyclose
	res, body = doRequestCredentialJSON(t, client, http.MethodGet, "result/"+state, "ResultToken "+bobResultToken, "", nil)
	require.Equal(t, http.StatusNotFound, res.StatusCode, body)
	//nolint:bodyclose
	res, body = doRequestCredentialJSON(t, client, http.MethodGet, "result/"+state, "ResultToken "+resultTokenPrefix+"wrong", "", nil)
	require.Equal(t, http.StatusNotFound, res.StatusCode, body)

	// Result tokens must use the ResultToken scheme, and only work to retrieve results
	//nolint:bodyclose
	res, body = doRequestCredentialJSON(t, client, http.MethodGet, "result/"+state, "Bearer "+resultToken, "", nil)
	require.Equal(t, http.StatusNotFound, res.StatusCode, body)
	//nolint:bodyclose
	res, body = doRequestCredentialJSON(t, client, http.MethodGet, "pubkey", "ResultToken "+resultToken, "", nil)
	require.Equal(t, http.StatusUnauthorized, res.StatusCode, body)

	// When the header is set, it must match the request's user
	//nolint:bodyclose
	res, body = doRequestCredentialJSON(t, client, http.MethodGet, "result/"+state, "ResultToken "+resultToken, bob.ID, nil)
	require.Equal(t, http.StatusForbidden, res.StatusCode, body)

	// Confirm the request, then retrieve the result with the result token
	browserPriv, err := ecdh.P256().GenerateKey(rand.Reader)
	require.NoError(t, err)
	browserJWK, err := protocolv2.ECP256PublicJWKFromECDH(browserPriv.PublicKey())
	require.NoError(t, err)
	//nolint:bodyclose
	res, body = doSessionPostJSON(t, client, "/v2/api/confirm", sessionCookie, map[string]any{
		"state":            state,
		"confirm":          true,
		"responseEnvelope": newV2ResponseEnvelope(browserJWK),
	})
	require.Equal(t, http.StatusOK, res.StatusCode, body)

	//nolint:bodyclose
	res, body = doRequestCredentialJSON(t, client, http.MethodGet, "result/"+state, "ResultToken "+resultToken, alice.ID, nil)
	require.Equal(t, http.StatusOK, res.StatusCode, body)
	require.Equal(t, true, body["done"])
}

func TestServerRequestUserHeaderWithStaticKey(t *testing.T) {
	setTestConfig(t, "v2-user-header.db")
	srv := newTestServer(t, nil, nil, nil)
	startTestServer(t, srv)
	client := clientForListener(srv.appListener)

	_, alice := seedV2SessionCookie(t, srv, "user-alice", "Alice")

	// The header is optional with a static key, but must match when set
	//nolint:bodyclose
	res, body := doRequestCredentialJSON(t, client, http.MethodGet, "pubkey", "RequestKey "+alice.RequestKey, "", nil)
	require.Equal(t, http.StatusOK, res.StatusCode, body)

	//nolint:bodyclose
	res, body = doRequestCredentialJSON(t, client, http.MethodGet, "pubkey", "RequestKey "+alice.RequestKey, alice.ID, nil)
	require.Equal(t, http.StatusOK, res.StatusCode, body)

	//nolint:bodyclose
	res, body = doRequestCredentialJSON(t, client, http.MethodGet, "pubkey", "RequestKey "+alice.RequestKey, "user-bob", nil)
	require.Equal(t, http.StatusForbidden, res.StatusCode, body)
}

func TestServerRequestAuthorizationSchemes(t *testing.T) {
	iss := requestjwt.NewTestIssuer(t)
	srv, client := newOIDCTestServer(t, iss)

	_, alice := seedV2SessionCookie(t, srv, "user-alice", "Alice")
	_, bob := seedV2SessionCookie(t, srv, "user-bob", "Bob")
	const subject = "repo:example/app:environment:release"
	enableOIDCForUser(t, srv, bob.ID, iss, subject)
	token := iss.Token(subject, testOIDCAudience)

	tests := []struct {
		name          string
		authorization string
		userID        string
		expected      int
	}{
		{name: "request key with the RequestKey scheme", authorization: "RequestKey " + alice.RequestKey, expected: http.StatusOK},
		{name: "request key with a lowercase scheme", authorization: "requestkey " + alice.RequestKey, expected: http.StatusOK},
		{name: "request key with the Bearer scheme", authorization: "Bearer " + alice.RequestKey, expected: http.StatusOK},
		{name: "request key without a scheme", authorization: alice.RequestKey, expected: http.StatusOK},
		{name: "JWT with the Bearer scheme", authorization: "Bearer " + token, userID: bob.ID, expected: http.StatusOK},
		// JWTs must use the Bearer scheme, otherwise they're treated as request keys, which don't exist
		{name: "JWT with the RequestKey scheme", authorization: "RequestKey " + token, userID: bob.ID, expected: http.StatusNotFound},
		{name: "JWT without a scheme", authorization: token, userID: bob.ID, expected: http.StatusNotFound},
		{name: "unsupported scheme", authorization: "Basic dXNlcjpwYXNz", expected: http.StatusUnauthorized},
		{name: "missing", authorization: "", expected: http.StatusUnauthorized},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			//nolint:bodyclose
			res, body := doRequestCredentialJSON(t, client, http.MethodGet, "pubkey", tt.authorization, tt.userID, nil)
			require.Equal(t, tt.expected, res.StatusCode, body)
		})
	}
}

func TestServerRequestOIDCSettingsRoutes(t *testing.T) {
	setTestConfig(t, "v2-oidc-settings.db")
	srv := newTestServer(t, nil, nil, nil)
	startTestServer(t, srv)
	client := clientForListener(srv.appListener)

	cookie, alice := seedV2SessionCookie(t, srv, "user-alice", "Alice")

	// Add an issuer
	//nolint:bodyclose
	res, body := doSessionPostJSON(t, client, "/v2/auth/request-oidc-issuers/add", cookie, map[string]any{
		"displayName": "Release workflow",
		"issuer":      "https://token.actions.githubusercontent.com",
		"audience":    testOIDCAudience,
		"subject":     "repo:example/app:ref:refs/tags/*",
	})
	require.Equal(t, http.StatusOK, res.StatusCode, body)
	issuers, _ := body["requestOidcIssuers"].([]any)
	require.Len(t, issuers, 1)
	added, _ := issuers[0].(map[string]any)
	addedID, _ := added["id"].(string)
	require.NotEmpty(t, addedID)
	require.Equal(t, "Release workflow", added["displayName"])

	// Invalid issuers are rejected
	invalid := []map[string]any{
		{"issuer": "http://insecure.example.com", "audience": testOIDCAudience, "subject": "a"},
		{"issuer": "https://issuer.example.com", "audience": "", "subject": "a"},
		{"issuer": "https://issuer.example.com", "audience": testOIDCAudience, "subject": "*"},
		{"issuer": "not-a-url", "audience": testOIDCAudience, "subject": "a"},
		{"issuer": "https://issuer.example.com", "audience": testOIDCAudience, "subject": "a", "displayName": strings.Repeat("n", requestjwt.MaxDisplayNameLength+1)},
	}
	for i, in := range invalid {
		//nolint:bodyclose
		res, body = doSessionPostJSON(t, client, "/v2/auth/request-oidc-issuers/add", cookie, in)
		require.Equal(t, http.StatusBadRequest, res.StatusCode, "case %d: %v", i, body)
	}

	// Enable OIDC tokens and disable the request key
	//nolint:bodyclose
	res, body = doSessionPostJSON(t, client, "/v2/auth/request-auth-methods", cookie, map[string]any{"requestKeyEnabled": false, "requestOidcEnabled": true})
	require.Equal(t, http.StatusOK, res.StatusCode, body)
	require.Equal(t, false, body["requestKeyEnabled"])
	require.Equal(t, true, body["requestOidcEnabled"])

	// Both fields are required
	//nolint:bodyclose
	res, body = doSessionPostJSON(t, client, "/v2/auth/request-auth-methods", cookie, map[string]any{"requestOidcEnabled": true})
	require.Equal(t, http.StatusBadRequest, res.StatusCode, body)

	// The session reflects the changes
	user, err := srv.db.AuthStore().GetUserByID(t.Context(), alice.ID)
	require.NoError(t, err)
	info := sessionInfoFromUser(user, 0)
	require.False(t, info.RequestKeyEnabled)
	require.True(t, info.RequestOIDCEnabled)
	require.Len(t, info.RequestOIDCIssuers, 1)

	// Disabling OIDC tokens keeps the trusted issuers
	//nolint:bodyclose
	res, body = doSessionPostJSON(t, client, "/v2/auth/request-auth-methods", cookie, map[string]any{"requestKeyEnabled": true, "requestOidcEnabled": false})
	require.Equal(t, http.StatusOK, res.StatusCode, body)
	user, err = srv.db.AuthStore().GetUserByID(t.Context(), alice.ID)
	require.NoError(t, err)
	require.Len(t, user.RequestOIDC, 1)

	// Delete the issuer
	//nolint:bodyclose
	res, body = doSessionPostJSON(t, client, "/v2/auth/request-oidc-issuers/delete", cookie, map[string]any{"id": addedID})
	require.Equal(t, http.StatusOK, res.StatusCode, body)
	issuers, _ = body["requestOidcIssuers"].([]any)
	require.NotNil(t, issuers)
	require.Empty(t, issuers)

	//nolint:bodyclose
	res, body = doSessionPostJSON(t, client, "/v2/auth/request-oidc-issuers/delete", cookie, map[string]any{"id": addedID})
	require.Equal(t, http.StatusNotFound, res.StatusCode, body)

	// Every change is audited
	for _, eventType := range []db.EventType{db.AuditAuthOIDCIssuerAdd, db.AuditAuthOIDCIssuerDelete} {
		events, _, err := srv.db.AuditStore().List(t.Context(), db.AuditFilter{UserID: alice.ID, EventType: eventType}, 10, "")
		require.NoError(t, err)
		require.Len(t, events, 1, "event %s", eventType)
	}
	events, _, err := srv.db.AuditStore().List(t.Context(), db.AuditFilter{UserID: alice.ID, EventType: db.AuditAuthRequestAuthMethods}, 10, "")
	require.NoError(t, err)
	require.Len(t, events, 2)
}
