//go:build unit

package server

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"

	"github.com/italypaleale/revaulter/pkg/config"
	"github.com/italypaleale/revaulter/pkg/protocolv2"
	"github.com/italypaleale/revaulter/pkg/utils/bufconn"
	"github.com/italypaleale/revaulter/pkg/utils/webhook"
	"github.com/italypaleale/revaulter/pkg/v2db"
)

const (
	testServerPort = 5701
	bufconnBufSize = 1 << 20 // 1MB
)

func TestMain(m *testing.M) {
	_ = config.SetTestConfig(map[string]any{
		"logLevel":            "info",
		"port":                testServerPort,
		"bind":                "127.0.0.1",
		"sessionTimeout":      5 * time.Minute,
		"requestTimeout":      5 * time.Minute,
		"webhookUrl":          "http://test.local",
		"databaseDSN":         ":memory:",
		"secretKey":           "dGVzdC12Mi1kYi1rZXk",
		"cookieEncryptionKey": "hello-world",
		"tokenSigningKey":     "hello-world",
	})

	gin.SetMode(gin.ReleaseMode)
	os.Exit(m.Run())
}

func TestServerV2RequestLifecycle(t *testing.T) {
	tmpDir := t.TempDir()
	t.Cleanup(config.SetTestConfig(map[string]any{
		"databaseDSN":     tmpDir + "/v2-req.db",
		"secretKey":       "dGVzdC12Mi1kYi1rZXk",
		"baseUrl":         fmt.Sprintf("https://localhost:%d", testServerPort),
		"webauthnOrigins": []string{fmt.Sprintf("https://localhost:%d", testServerPort)},
	}))

	srv, cleanup := newTestServer(t, nil, nil, nil)
	require.NotNil(t, srv)
	defer cleanup()

	stopServerFn := startTestServer(t, srv)
	defer stopServerFn(t)
	client := clientForListener(srv.appListener)

	doPostJSON := func(t *testing.T, path string, body any, cookies ...*http.Cookie) (*http.Response, map[string]any) {
		t.Helper()
		b, err := json.Marshal(body)
		require.NoError(t, err)
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, fmt.Sprintf("https://localhost:%d%s", testServerPort, path), bytes.NewReader(b))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")
		for _, c := range cookies {
			if c != nil {
				req.AddCookie(c)
			}
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

	doGetJSON := func(t *testing.T, path string, cookies ...*http.Cookie) (*http.Response, map[string]any) {
		t.Helper()
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, fmt.Sprintf("https://localhost:%d%s", testServerPort, path), nil)
		require.NoError(t, err)
		for _, c := range cookies {
			if c != nil {
				req.AddCookie(c)
			}
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

	sessionCookie, aliceUser := seedV2SessionCookie(t, srv, "user-alice", "Alice")

	// Build JWK for client transport key
	clientPriv, err := ecdh.P256().GenerateKey(rand.Reader)
	require.NoError(t, err)
	clientJWK, err := protocolv2.ECP256PublicJWKFromECDH(clientPriv.PublicKey())
	require.NoError(t, err)

	// Create request
	res, createResp := doPostJSON(t, "/v2/request/"+aliceUser.RequestKey+"/encrypt", newV2CreateRequestBody("disk-key", "aes-gcm-256", clientJWK))
	require.Equal(t, http.StatusAccepted, res.StatusCode)
	state, _ := createResp["state"].(string)
	require.NotEmpty(t, state)

	// List pending request for alice
	resList, err := func() (*http.Response, error) {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, fmt.Sprintf("https://localhost:%d/v2/api/list", testServerPort), nil)
		if err != nil {
			return nil, err
		}
		req.AddCookie(sessionCookie)
		return client.Do(req)
	}()
	require.NoError(t, err)
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		resList.Body.Close()
	}()
	require.Equal(t, http.StatusOK, resList.StatusCode)
	var list []map[string]any
	require.NoError(t, json.NewDecoder(resList.Body).Decode(&list))
	require.Len(t, list, 1)
	require.Equal(t, state, list[0]["state"])

	// Get request details
	res, detail := doGetJSON(t, "/v2/api/request/"+state, sessionCookie)
	require.Equal(t, http.StatusOK, res.StatusCode)
	require.Equal(t, aliceUser.ID, detail["userId"])
	reqObj, ok := detail["encryptedRequest"].(map[string]any)
	require.True(t, ok)
	require.NotNil(t, reqObj["cliEphemeralPublicKey"])

	// Confirm with a valid-looking encrypted response envelope
	browserPriv, err := ecdh.P256().GenerateKey(rand.Reader)
	require.NoError(t, err)
	browserJWK, err := protocolv2.ECP256PublicJWKFromECDH(browserPriv.PublicKey())
	require.NoError(t, err)
	res, confirmResp := doPostJSON(t, "/v2/api/confirm", map[string]any{
		"state":            state,
		"confirm":          true,
		"responseEnvelope": newV2ResponseEnvelope(browserJWK),
	}, sessionCookie)
	require.Equal(t, http.StatusOK, res.StatusCode)
	require.Equal(t, true, confirmResp["confirmed"])

	// Result endpoint returns completed envelope
	res, result := doGetJSON(t, "/v2/request/result/"+state)
	require.Equal(t, http.StatusOK, res.StatusCode)
	require.Equal(t, state, result["state"])
	require.Equal(t, true, result["done"])
	_, ok = result["responseEnvelope"].(map[string]any)
	require.True(t, ok)
}

func TestServerV2PublicSignup(t *testing.T) {
	tmpDir := t.TempDir()
	t.Cleanup(config.SetTestConfig(map[string]any{
		"databaseDSN":     tmpDir + "/v2-users.db",
		"secretKey":       "dGVzdC12Mi1kYi1rZXk",
		"baseUrl":         fmt.Sprintf("https://localhost:%d", testServerPort),
		"webauthnOrigins": []string{fmt.Sprintf("https://localhost:%d", testServerPort)},
	}))

	srv, cleanup := newTestServer(t, nil, nil, nil)
	require.NotNil(t, srv)
	defer cleanup()

	stopServerFn := startTestServer(t, srv)
	defer stopServerFn(t)
	client := clientForListener(srv.appListener)

	doPostJSON := func(t *testing.T, path string, body any, cookies ...*http.Cookie) (*http.Response, map[string]any) {
		t.Helper()
		b, err := json.Marshal(body)
		require.NoError(t, err)
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, fmt.Sprintf("https://localhost:%d%s", testServerPort, path), bytes.NewReader(b))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")
		for _, c := range cookies {
			if c != nil {
				req.AddCookie(c)
			}
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

	_, _ = seedV2SessionCookie(t, srv, "user-alice", "Alice")

	// Public signup remains available for later users
	res, regBegin := doPostJSON(t, "/v2/auth/register/begin", map[string]any{"displayName": "Bob"})
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		res.Body.Close()
	}()
	require.Equal(t, http.StatusOK, res.StatusCode)
	require.NotEmpty(t, regBegin["challengeId"])
	require.Equal(t, "webauthn", regBegin["mode"])
}

func TestServerV2SessionMiddlewareBlocksUnreadyUsersFromAPI(t *testing.T) {
	tmpDir := t.TempDir()
	t.Cleanup(config.SetTestConfig(map[string]any{
		"databaseDSN":     tmpDir + "/v2-unready.db",
		"secretKey":       "dGVzdC12Mi1kYi1rZXk",
		"baseUrl":         fmt.Sprintf("https://localhost:%d", testServerPort),
		"webauthnOrigins": []string{fmt.Sprintf("https://localhost:%d", testServerPort)},
	}))

	srv, cleanup := newTestServer(t, nil, nil, nil)
	require.NotNil(t, srv)
	defer cleanup()

	stopServerFn := startTestServer(t, srv)
	defer stopServerFn(t)
	client := clientForListener(srv.appListener)

	sessionCookie, _ := seedV2SessionCookie(t, srv, "user-unready", "Unready")
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, fmt.Sprintf("https://localhost:%d/v2/api/list", testServerPort), nil)
	require.NoError(t, err)
	req.AddCookie(sessionCookie)

	res, err := client.Do(req)
	require.NoError(t, err)
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		res.Body.Close()
	}()

	var body map[string]any
	_ = json.NewDecoder(res.Body).Decode(&body)
	require.Equal(t, http.StatusForbidden, res.StatusCode)
	require.Equal(t, "User account setup is not complete", body["error"])
}

func TestServerV2SessionEndpointAllowsUnreadyUsers(t *testing.T) {
	tmpDir := t.TempDir()
	t.Cleanup(config.SetTestConfig(map[string]any{
		"databaseDSN":     tmpDir + "/v2-session-unready.db",
		"secretKey":       "dGVzdC12Mi1kYi1rZXk",
		"baseUrl":         fmt.Sprintf("https://localhost:%d", testServerPort),
		"webauthnOrigins": []string{fmt.Sprintf("https://localhost:%d", testServerPort)},
	}))

	srv, cleanup := newTestServer(t, nil, nil, nil)
	require.NotNil(t, srv)
	defer cleanup()

	stopServerFn := startTestServer(t, srv)
	defer stopServerFn(t)
	client := clientForListener(srv.appListener)

	sessionCookie, _ := seedV2SessionCookie(t, srv, "user-unready-session", "Unready Session")
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, fmt.Sprintf("https://localhost:%d/v2/auth/session", testServerPort), nil)
	require.NoError(t, err)
	req.AddCookie(sessionCookie)

	res, err := client.Do(req)
	require.NoError(t, err)
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		res.Body.Close()
	}()

	var body map[string]any
	_ = json.NewDecoder(res.Body).Decode(&body)
	require.Equal(t, http.StatusOK, res.StatusCode)
	require.Equal(t, true, body["authenticated"])
	require.Equal(t, "user-unready-session", body["userId"])
}

func TestServerV2DisableSignup(t *testing.T) {
	tmpDir := t.TempDir()
	t.Cleanup(config.SetTestConfig(map[string]any{
		"databaseDSN":     tmpDir + "/v2-disable-signup.db",
		"secretKey":       "dGVzdC12Mi1kYi1rZXk",
		"baseUrl":         fmt.Sprintf("https://localhost:%d", testServerPort),
		"webauthnOrigins": []string{fmt.Sprintf("https://localhost:%d", testServerPort)},
		"disableSignup":   true,
	}))

	srv, cleanup := newTestServer(t, nil, nil, nil)
	require.NotNil(t, srv)
	defer cleanup()

	stopServerFn := startTestServer(t, srv)
	defer stopServerFn(t)
	client := clientForListener(srv.appListener)

	body, err := json.Marshal(map[string]any{"displayName": "Alice"})
	require.NoError(t, err)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, fmt.Sprintf("https://localhost:%d/v2/auth/register/begin", testServerPort), bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	res, err := client.Do(req)
	require.NoError(t, err)
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		res.Body.Close()
	}()
	require.Equal(t, http.StatusForbidden, res.StatusCode)
}

func TestServerV2SecurityAndExpiryScenarios(t *testing.T) {
	tmpDir := t.TempDir()
	t.Cleanup(config.SetTestConfig(map[string]any{
		"databaseDSN":     tmpDir + "/v2-security.db",
		"secretKey":       "dGVzdC12Mi1kYi1rZXk",
		"baseUrl":         fmt.Sprintf("https://localhost:%d", testServerPort),
		"webauthnOrigins": []string{fmt.Sprintf("https://localhost:%d", testServerPort)},
	}))

	srv, cleanup := newTestServer(t, nil, nil, nil)
	require.NotNil(t, srv)
	defer cleanup()

	stopServerFn := startTestServer(t, srv)
	defer stopServerFn(t)
	client := clientForListener(srv.appListener)

	doPostJSON := func(t *testing.T, path string, body any, cookies ...*http.Cookie) (*http.Response, map[string]any) {
		t.Helper()
		b, err := json.Marshal(body)
		require.NoError(t, err)
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, fmt.Sprintf("https://localhost:%d%s", testServerPort, path), bytes.NewReader(b))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")
		for _, c := range cookies {
			if c != nil {
				req.AddCookie(c)
			}
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
	doGetJSON := func(t *testing.T, path string, cookies ...*http.Cookie) (*http.Response, map[string]any) {
		t.Helper()
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, fmt.Sprintf("https://localhost:%d%s", testServerPort, path), nil)
		require.NoError(t, err)
		for _, c := range cookies {
			if c != nil {
				req.AddCookie(c)
			}
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
	aliceCookie, aliceUser := seedV2SessionCookie(t, srv, "user-alice", "Alice")

	clientPriv, err := ecdh.P256().GenerateKey(rand.Reader)
	require.NoError(t, err)
	clientJWK, err := protocolv2.ECP256PublicJWKFromECDH(clientPriv.PublicKey())
	require.NoError(t, err)

	// Reject malformed client transport JWK (private material present).
	invalidCreateBody := newV2CreateRequestBody("disk-key", "aes-gcm-256", clientJWK)
	invalidCreateBody["cliEphemeralPublicKey"] = map[string]any{
		"kty": "EC", "crv": "P-256",
		"x": clientJWK.X, "y": clientJWK.Y,
		"d": "forbidden",
	}
	res, _ := doPostJSON(t, "/v2/request/"+aliceUser.RequestKey+"/encrypt", invalidCreateBody)
	require.Equal(t, http.StatusBadRequest, res.StatusCode)

	// Create a valid request targeted to alice.
	res, create := doPostJSON(t, "/v2/request/"+aliceUser.RequestKey+"/encrypt", newV2CreateRequestBody("disk-key", "aes-gcm-256", clientJWK))
	require.Equal(t, http.StatusAccepted, res.StatusCode)
	state, _ := create["state"].(string)
	require.NotEmpty(t, state)

	// Alice sees the request.
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, fmt.Sprintf("https://localhost:%d/v2/api/list", testServerPort), nil)
	require.NoError(t, err)
	req.AddCookie(aliceCookie)
	resList, err := client.Do(req)
	require.NoError(t, err)
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		resList.Body.Close()
	}()
	require.Equal(t, http.StatusOK, resList.StatusCode)
	var list []map[string]any
	require.NoError(t, json.NewDecoder(resList.Body).Decode(&list))
	require.Len(t, list, 1)
	require.Equal(t, state, list[0]["state"])

	// Reject malformed response envelope from Alice.
	invalidEnvelope := newV2ResponseEnvelope(clientJWK)
	invalidEnvelope["browserEphemeralPublicKey"] = map[string]any{
		"kty": "EC", "crv": "P-256",
		"x": clientJWK.X, "y": clientJWK.Y,
		"d": "forbidden",
	}
	res, _ = doPostJSON(t, "/v2/api/confirm", map[string]any{
		"state":            state,
		"confirm":          true,
		"responseEnvelope": invalidEnvelope,
	}, aliceCookie)
	require.Equal(t, http.StatusBadRequest, res.StatusCode)

	// Reject response envelope with malformed transport fields.
	browserPriv, err := ecdh.P256().GenerateKey(rand.Reader)
	require.NoError(t, err)
	browserJWK, err := protocolv2.ECP256PublicJWKFromECDH(browserPriv.PublicKey())
	require.NoError(t, err)
	invalidNonceEnvelope := newV2ResponseEnvelope(browserJWK)
	invalidNonceEnvelope["nonce"] = "!!!!"
	res, _ = doPostJSON(t, "/v2/api/confirm", map[string]any{
		"state":            state,
		"confirm":          true,
		"responseEnvelope": invalidNonceEnvelope,
	}, aliceCookie)
	require.Equal(t, http.StatusBadRequest, res.StatusCode)

	// Expiry path: short timeout should transition to failed/expired on result polling.
	expiringCreateBody := newV2CreateRequestBody("expiring-key", "aes-gcm-256", clientJWK)
	expiringCreateBody["timeout"] = "1s"
	res, create = doPostJSON(t, "/v2/request/"+aliceUser.RequestKey+"/encrypt", expiringCreateBody)
	require.Equal(t, http.StatusAccepted, res.StatusCode)
	expState, _ := create["state"].(string)
	require.NotEmpty(t, expState)
	time.Sleep(1500 * time.Millisecond)
	res, result := doGetJSON(t, "/v2/request/result/"+expState)
	require.Equal(t, http.StatusConflict, res.StatusCode)
	require.Equal(t, true, result["failed"])
}

func TestServerV2RegisterRequiresWebAuthn(t *testing.T) {
	tmpDir := t.TempDir()
	t.Cleanup(config.SetTestConfig(map[string]any{
		"databaseDSN":     tmpDir + "/v2-register-requires-webauthn.db",
		"secretKey":       "dGVzdC12Mi1kYi1rZXk",
		"baseUrl":         fmt.Sprintf("https://localhost:%d", testServerPort),
		"webauthnOrigins": []string{fmt.Sprintf("https://localhost:%d", testServerPort)},
	}))

	srv, cleanup := newTestServer(t, nil, nil, nil)
	require.NotNil(t, srv)
	defer cleanup()
	srv.webAuthn = nil

	stopServerFn := startTestServer(t, srv)
	defer stopServerFn(t)
	client := clientForListener(srv.appListener)

	body := bytes.NewBufferString(`{"displayName":"Alice"}`)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, fmt.Sprintf("https://localhost:%d/v2/auth/register/begin", testServerPort), body)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	res, err := client.Do(req)
	require.NoError(t, err)
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		res.Body.Close()
	}()
	require.Equal(t, http.StatusServiceUnavailable, res.StatusCode)
}

func TestServerV2CreateRequestSendsWebhook(t *testing.T) {
	tmpDir := t.TempDir()
	t.Cleanup(config.SetTestConfig(map[string]any{
		"databaseDSN":     tmpDir + "/v2-webhook.db",
		"secretKey":       "dGVzdC12Mi1kYi1rZXk",
		"baseUrl":         fmt.Sprintf("https://localhost:%d", testServerPort),
		"webauthnOrigins": []string{fmt.Sprintf("https://localhost:%d", testServerPort)},
	}))

	webhookRequests := make(chan *webhook.WebhookRequest, 1)
	srv, cleanup := newTestServer(t, &mockWebhook{requests: webhookRequests}, nil, nil)
	require.NotNil(t, srv)
	defer cleanup()
	stopServerFn := startTestServer(t, srv)
	defer stopServerFn(t)
	client := clientForListener(srv.appListener)

	clientPriv, err := ecdh.P256().GenerateKey(rand.Reader)
	require.NoError(t, err)
	clientJWK, err := protocolv2.ECP256PublicJWKFromECDH(clientPriv.PublicKey())
	require.NoError(t, err)

	_, aliceUser := seedV2SessionCookie(t, srv, "user-alice", "Alice")

	createBody := newV2CreateRequestBody("disk-key", "aes-gcm-256", clientJWK)
	createBody["note"] = "boot unlock"
	body, err := json.Marshal(createBody)
	require.NoError(t, err)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, fmt.Sprintf("https://localhost:%d/v2/request/%s/encrypt", testServerPort, aliceUser.RequestKey), bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	res, err := client.Do(req)
	require.NoError(t, err)
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		res.Body.Close()
	}()
	require.Equal(t, http.StatusAccepted, res.StatusCode)

	select {
	case <-time.After(2 * time.Second):
		t.Fatal("did not receive webhook notification")
	case msg := <-webhookRequests:
		require.NotNil(t, msg)
		require.Equal(t, "v2", msg.Flow)
		require.Equal(t, "encrypt", msg.OperationName)
		require.Equal(t, "Alice", msg.AssignedUser)
		require.Equal(t, "disk-key", msg.KeyLabel)
		require.Equal(t, "aes-gcm-256", msg.Algorithm)
		require.Equal(t, "boot unlock", msg.Note)
		require.NotEmpty(t, msg.StateId)
	}
}

func newTestServer(t *testing.T, wh *mockWebhook, httpClientTransport http.RoundTripper, logDest io.Writer) (*Server, func()) {
	t.Helper()

	if logDest == nil {
		logDest = io.Discard
	}

	log := slog.
		New(slog.NewTextHandler(io.MultiWriter(os.Stdout, logDest), nil)).
		With(slog.String("app", "test"))
	if wh == nil {
		wh = &mockWebhook{}
	}

	cert, key, err := getSelfSignedTLSCredentials()
	require.NoError(t, err, "cannot get TLS credentials")

	cleanup := config.SetTestConfig(map[string]any{
		"tLSCertPEM": cert,
		"tLSKeyPEM":  key,
	})

	srv, err := NewServer(NewServerOpts{
		Log:     log,
		Webhook: wh,
	})
	require.NoError(t, err)

	srv.appListener = bufconn.Listen(bufconnBufSize)

	if httpClientTransport != nil {
		srv.httpClient.Transport = httpClientTransport
	}

	return srv, cleanup
}

func seedV2SessionCookie(t *testing.T, srv *Server, userID string, displayName string) (*http.Cookie, *v2db.User) {
	t.Helper()

	sess, err := srv.authStore.RegisterUser(t.Context(), v2db.RegisterUserInput{
		UserID:         userID,
		DisplayName:    displayName,
		WebAuthnUserID: base64.RawURLEncoding.EncodeToString([]byte("webauthn-" + userID)),
		CredentialID:   "cred-" + userID,
		PublicKey:      `{}`,
		SignCount:      1,
		SessionTTL:     config.Get().SessionTimeout,
	})
	require.NoError(t, err)

	requestEncPriv, err := ecdh.P256().GenerateKey(rand.Reader)
	require.NoError(t, err)
	requestEncJWK, err := protocolv2.ECP256PublicJWKFromECDH(requestEncPriv.PublicKey())
	require.NoError(t, err)
	requestEncJWKJSON, err := json.Marshal(requestEncJWK)
	require.NoError(t, err)
	err = srv.authStore.FinalizeSignup(
		t.Context(),
		userID,
		"test-canary",
		string(requestEncJWKJSON),
		base64.RawURLEncoding.EncodeToString([]byte("test-mlkem-pubkey")),
	)
	require.NoError(t, err)

	user, err := srv.authStore.GetUserByID(t.Context(), userID)
	require.NoError(t, err)
	require.NotNil(t, user)

	cookieValue, err := serializeSecureCookieEncryptedJWT(sessionCookieNameSecure, sess.ID, time.Until(sess.ExpiresAt))
	require.NoError(t, err)

	return &http.Cookie{
		Name:  sessionCookieNameSecure,
		Value: cookieValue,
		Path:  "/",
	}, user
}

func startTestServer(t *testing.T, srv *Server) func(t *testing.T) {
	t.Helper()

	// Start the server in a background goroutine
	srvCtx, srvCancel := context.WithCancel(t.Context())
	startErrCh := make(chan error, 1)
	go func() {
		startErrCh <- srv.Run(srvCtx)
	}()

	// Ensure the server has started and there's no error
	// This may report false positives if the server just takes longer to start, but we'll still catch those errors later on
	select {
	case <-time.After(100 * time.Millisecond):
		// all good
	case err := <-startErrCh:
		t.Fatalf("Received an unexpected error in startErrCh: %v", err)
	}

	// Return a function to tear down the test server, which must be invoked at the end of the test
	return func(t *testing.T) {
		t.Helper()

		// Shutdown the server
		srvCancel()

		// At the end of the test, there should be no error
		require.NoError(t, <-startErrCh, "received an unexpected error in startErrCh")
	}
}

func clientForListener(ln net.Listener) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()      //nolint:forcetypeassert
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec
	transport.DialContext = func(ctx context.Context, _ string, _ string) (net.Conn, error) {
		bl, ok := ln.(*bufconn.Listener)
		if !ok {
			return nil, errors.New("failed to cast listener to bufconn.Listener")
		}
		return bl.DialContext(ctx)
	}

	return &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func newV2CreateRequestBody(keyLabel string, algorithm string, cliJWK protocolv2.ECP256PublicJWK) map[string]any {
	return map[string]any{
		"keyLabel":      keyLabel,
		"algorithm":     algorithm,
		"requestEncAlg": "ecdh-p256+mlkem768+a256gcm",
		"cliEphemeralPublicKey": map[string]any{
			"kty": cliJWK.Kty,
			"crv": cliJWK.Crv,
			"x":   cliJWK.X,
			"y":   cliJWK.Y,
		},
		"mlkemCiphertext":       base64.RawURLEncoding.EncodeToString([]byte("test-mlkem-ciphertext")),
		"encryptedPayloadNonce": base64.RawURLEncoding.EncodeToString([]byte("123456789012")),
		"encryptedPayload":      base64.RawURLEncoding.EncodeToString([]byte("test-request-ciphertext")),
	}
}

func newV2ResponseEnvelope(browserJWK protocolv2.ECP256PublicJWK) map[string]any {
	return map[string]any{
		"transportAlg": "ecdh-p256+mlkem768+a256gcm",
		"browserEphemeralPublicKey": map[string]any{
			"kty": browserJWK.Kty,
			"crv": browserJWK.Crv,
			"x":   browserJWK.X,
			"y":   browserJWK.Y,
		},
		"mlkemCiphertext": base64.RawURLEncoding.EncodeToString([]byte("test-response-mlkem-ciphertext")),
		"nonce":           base64.RawURLEncoding.EncodeToString([]byte("123456789012")),
		"ciphertext":      base64.RawURLEncoding.EncodeToString([]byte("test-response-ciphertext")),
		"resultType":      "bytes",
	}
}

func getSelfSignedTLSCredentials() (certPem []byte, keyPem []byte, err error) {
	pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	now := time.Now()
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test"},
		},
		NotBefore:             now.Add(-1 * time.Minute),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
	}

	certDer, err := x509.CreateCertificate(rand.Reader, &template, &template, pk.Public(), pk)
	if err != nil {
		return nil, nil, err
	}
	certPem = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDer})

	keyDer, err := x509.MarshalPKCS8PrivateKey(pk)
	if err != nil {
		return nil, nil, err
	}

	keyPem = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDer})

	return certPem, keyPem, nil
}

// mockWebhook implements the Webhook interface
type mockWebhook struct {
	requests chan *webhook.WebhookRequest
}

func (w mockWebhook) SendWebhook(_ context.Context, data *webhook.WebhookRequest) error {
	if w.requests != nil {
		w.requests <- data
	}
	return nil
}

func (w mockWebhook) SetBaseURL(val string) {
	// Nop
}
