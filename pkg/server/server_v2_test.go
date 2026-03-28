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

func TestServerV2RequestLifecyclePlaceholderAuth(t *testing.T) {
	tmpDir := t.TempDir()
	t.Cleanup(config.SetTestConfig(map[string]any{
		"databaseDSN":        tmpDir + "/v2-req.db",
		"secretKey":          "dGVzdC12Mi1kYi1rZXk",
		"baseUrl":            fmt.Sprintf("https://localhost:%d", testServerPort),
		"origins":            []string{fmt.Sprintf("https://localhost:%d", testServerPort)},
	}))

	srv, cleanup := newTestServer(t, nil, nil, nil)
	require.NotNil(t, srv)
	defer cleanup()
	srv.webAuthn = nil
	srv.v2AllowAuthPlaceholder = true

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
		defer closeBody(res)
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
		defer closeBody(res)
		var out map[string]any
		_ = json.NewDecoder(res.Body).Decode(&out)
		return res, out
	}

	// Register first admin (placeholder path)
	res, regBegin := doPostJSON(t, "/v2/auth/register/begin", map[string]any{
		"username":    "alice",
		"displayName": "Alice",
	})
	require.Equal(t, http.StatusOK, res.StatusCode)
	res, _ = doPostJSON(t, "/v2/auth/register/finish", map[string]any{
		"username":    "alice",
		"displayName": "Alice",
		"challengeId": regBegin["challengeId"],
		"credential": map[string]any{
			"id":        "cred-alice",
			"publicKey": `{"placeholder":true}`,
			"signCount": 1,
		},
	})
	require.Equal(t, http.StatusOK, res.StatusCode)
	var sessionCookie *http.Cookie
	for _, c := range res.Cookies() {
		if c.Name == sessionCookieName {
			sessionCookie = c
			break
		}
	}
	require.NotNil(t, sessionCookie)

	// Build JWK for client transport key
	clientPriv, err := ecdh.P256().GenerateKey(rand.Reader)
	require.NoError(t, err)
	clientJWK, err := protocolv2.ECP256PublicJWKFromECDH(clientPriv.PublicKey())
	require.NoError(t, err)

	// Create request
	res, createResp := doPostJSON(t, "/v2/request/encrypt", map[string]any{
		"targetUser": "alice",
		"keyLabel":   "disk-key",
		"algorithm":  "aes-gcm-256",
		"value":      base64.RawURLEncoding.EncodeToString([]byte("hello")),
		"clientTransportKey": map[string]any{
			"kty": clientJWK.Kty,
			"crv": clientJWK.Crv,
			"x":   clientJWK.X,
			"y":   clientJWK.Y,
		},
	})
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
	defer closeBody(resList)
	require.Equal(t, http.StatusOK, resList.StatusCode)
	var list []map[string]any
	require.NoError(t, json.NewDecoder(resList.Body).Decode(&list))
	require.Len(t, list, 1)
	require.Equal(t, state, list[0]["state"])

	// Get request details
	res, detail := doGetJSON(t, "/v2/api/request/"+state, sessionCookie)
	require.Equal(t, http.StatusOK, res.StatusCode)
	require.Equal(t, "alice", detail["targetUser"])
	reqObj, ok := detail["request"].(map[string]any)
	require.True(t, ok)
	require.NotNil(t, reqObj["clientTransportKey"])

	// Confirm with a valid-looking encrypted response envelope
	browserPriv, err := ecdh.P256().GenerateKey(rand.Reader)
	require.NoError(t, err)
	browserJWK, err := protocolv2.ECP256PublicJWKFromECDH(browserPriv.PublicKey())
	require.NoError(t, err)
	res, confirmResp := doPostJSON(t, "/v2/api/confirm", map[string]any{
		"state":   state,
		"confirm": true,
		"responseEnvelope": map[string]any{
			"transportAlg": "ecdh-p256+a256gcm",
			"browserEphemeralPublicKey": map[string]any{
				"kty": browserJWK.Kty,
				"crv": browserJWK.Crv,
				"x":   browserJWK.X,
				"y":   browserJWK.Y,
			},
			"nonce":      base64.RawURLEncoding.EncodeToString([]byte("123456789012")),
			"ciphertext": base64.RawURLEncoding.EncodeToString([]byte("ciphertext+tag")),
			"aad":        base64.RawURLEncoding.EncodeToString([]byte(`{"v":1}`)),
			"resultType": "bytes",
		},
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

func TestServerV2AdminManagedRegisterPlaceholder(t *testing.T) {
	tmpDir := t.TempDir()
	t.Cleanup(config.SetTestConfig(map[string]any{
		"databaseDSN":        tmpDir + "/v2-admins.db",
		"secretKey":          "dGVzdC12Mi1kYi1rZXk",
		"baseUrl":            fmt.Sprintf("https://localhost:%d", testServerPort),
		"origins":            []string{fmt.Sprintf("https://localhost:%d", testServerPort)},
	}))

	srv, cleanup := newTestServer(t, nil, nil, nil)
	require.NotNil(t, srv)
	defer cleanup()
	srv.webAuthn = nil
	srv.v2AllowAuthPlaceholder = true

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
		defer closeBody(res)
		var out map[string]any
		_ = json.NewDecoder(res.Body).Decode(&out)
		return res, out
	}

	getSessionCookie := func(res *http.Response) *http.Cookie {
		for _, c := range res.Cookies() {
			if c.Name == sessionCookieName {
				return c
			}
		}
		return nil
	}

	// First admin self-register
	res, regBegin := doPostJSON(t, "/v2/auth/register/begin", map[string]any{"username": "alice", "displayName": "Alice"})
	require.Equal(t, http.StatusOK, res.StatusCode)
	res, _ = doPostJSON(t, "/v2/auth/register/finish", map[string]any{
		"username":    "alice",
		"displayName": "Alice",
		"challengeId": regBegin["challengeId"],
		"credential": map[string]any{
			"id":        "cred-alice",
			"publicKey": `{"placeholder":true}`,
			"signCount": 1,
		},
	})
	require.Equal(t, http.StatusOK, res.StatusCode)
	aliceCookie := getSessionCookie(res)
	require.NotNil(t, aliceCookie)

	// Public register is now closed
	res, _ = doPostJSON(t, "/v2/auth/register/begin", map[string]any{"username": "bob", "displayName": "Bob"})
	require.Equal(t, http.StatusConflict, res.StatusCode)

	// Admin-managed register begin/finish for bob
	res, adminRegBegin := doPostJSON(t, "/v2/auth/admin/register/begin", map[string]any{"username": "bob", "displayName": "Bob"}, aliceCookie)
	require.Equal(t, http.StatusOK, res.StatusCode)
	res, adminRegFinish := doPostJSON(t, "/v2/auth/admin/register/finish", map[string]any{
		"username":    "bob",
		"displayName": "Bob",
		"challengeId": adminRegBegin["challengeId"],
		"credential": map[string]any{
			"id":        "cred-bob",
			"publicKey": `{"placeholder":true}`,
			"signCount": 1,
		},
	}, aliceCookie)
	require.Equal(t, http.StatusOK, res.StatusCode)
	require.Equal(t, true, adminRegFinish["registered"])
	require.Equal(t, "bob", adminRegFinish["username"])

}

func TestServerV2ModeDisablesLegacyRoutes(t *testing.T) {
	tmpDir := t.TempDir()
	t.Cleanup(config.SetTestConfig(map[string]any{
		"databaseDSN": tmpDir + "/v2-only.db",
		"secretKey":   "dGVzdC12Mi1kYi1rZXk",
		"baseUrl":     fmt.Sprintf("https://localhost:%d", testServerPort),
		"origins":     []string{fmt.Sprintf("https://localhost:%d", testServerPort)},
	}))

	srv, cleanup := newTestServer(t, nil, nil, nil)
	require.NotNil(t, srv)
	defer cleanup()
	stopServerFn := startTestServer(t, srv)
	defer stopServerFn(t)
	client := clientForListener(srv.appListener)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, fmt.Sprintf("https://localhost:%d/request/encrypt", testServerPort), bytes.NewReader([]byte(`{}`)))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	res, err := client.Do(req)
	require.NoError(t, err)
	defer closeBody(res)
	require.Equal(t, http.StatusGone, res.StatusCode)

	req, err = http.NewRequestWithContext(t.Context(), http.MethodGet, fmt.Sprintf("https://localhost:%d/auth/signin", testServerPort), nil)
	require.NoError(t, err)
	res, err = client.Do(req)
	require.NoError(t, err)
	defer closeBody(res)
	require.Equal(t, http.StatusGone, res.StatusCode)
}

func TestServerV2SecurityAndExpiryScenarios(t *testing.T) {
	tmpDir := t.TempDir()
	t.Cleanup(config.SetTestConfig(map[string]any{
		"databaseDSN":        tmpDir + "/v2-security.db",
		"secretKey":          "dGVzdC12Mi1kYi1rZXk",
		"baseUrl":            fmt.Sprintf("https://localhost:%d", testServerPort),
		"origins":            []string{fmt.Sprintf("https://localhost:%d", testServerPort)},
	}))

	srv, cleanup := newTestServer(t, nil, nil, nil)
	require.NotNil(t, srv)
	defer cleanup()
	srv.webAuthn = nil
	srv.v2AllowAuthPlaceholder = true

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
		defer closeBody(res)
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
		defer closeBody(res)
		var out map[string]any
		_ = json.NewDecoder(res.Body).Decode(&out)
		return res, out
	}
	getSessionCookie := func(res *http.Response) *http.Cookie {
		for _, c := range res.Cookies() {
			if c.Name == sessionCookieName {
				return c
			}
		}
		return nil
	}
	registerFirst := func(t *testing.T, username, displayName, credID string) *http.Cookie {
		t.Helper()
		res, begin := doPostJSON(t, "/v2/auth/register/begin", map[string]any{
			"username":    username,
			"displayName": displayName,
		})
		require.Equal(t, http.StatusOK, res.StatusCode)
		res, _ = doPostJSON(t, "/v2/auth/register/finish", map[string]any{
			"username":    username,
			"displayName": displayName,
			"challengeId": begin["challengeId"],
			"credential": map[string]any{
				"id":        credID,
				"publicKey": `{"placeholder":true}`,
				"signCount": 1,
			},
		})
		require.Equal(t, http.StatusOK, res.StatusCode)
		c := getSessionCookie(res)
		require.NotNil(t, c)
		return c
	}
	_ = func(t *testing.T, actor *http.Cookie, username, displayName, credID string) {
		t.Helper()
		res, begin := doPostJSON(t, "/v2/auth/admin/register/begin", map[string]any{
			"username":    username,
			"displayName": displayName,
		}, actor)
		require.Equal(t, http.StatusOK, res.StatusCode)
		res, _ = doPostJSON(t, "/v2/auth/admin/register/finish", map[string]any{
			"username":    username,
			"displayName": displayName,
			"challengeId": begin["challengeId"],
			"credential": map[string]any{
				"id":        credID,
				"publicKey": `{"placeholder":true}`,
				"signCount": 1,
			},
		}, actor)
		require.Equal(t, http.StatusOK, res.StatusCode)
	}
	aliceCookie := registerFirst(t, "alice", "Alice", "cred-alice")

	clientPriv, err := ecdh.P256().GenerateKey(rand.Reader)
	require.NoError(t, err)
	clientJWK, err := protocolv2.ECP256PublicJWKFromECDH(clientPriv.PublicKey())
	require.NoError(t, err)

	// Reject malformed client transport JWK (private material present).
	res, _ := doPostJSON(t, "/v2/request/encrypt", map[string]any{
		"targetUser": "alice",
		"keyLabel":   "disk-key",
		"algorithm":  "aes-gcm-256",
		"value":      base64.RawURLEncoding.EncodeToString([]byte("hello")),
		"clientTransportKey": map[string]any{
			"kty": "EC", "crv": "P-256",
			"x": clientJWK.X, "y": clientJWK.Y,
			"d": "forbidden",
		},
	})
	require.Equal(t, http.StatusBadRequest, res.StatusCode)

	// Create a valid request targeted to alice.
	res, create := doPostJSON(t, "/v2/request/encrypt", map[string]any{
		"targetUser": "alice",
		"keyLabel":   "disk-key",
		"algorithm":  "aes-gcm-256",
		"value":      base64.RawURLEncoding.EncodeToString([]byte("hello")),
		"clientTransportKey": map[string]any{
			"kty": clientJWK.Kty, "crv": clientJWK.Crv, "x": clientJWK.X, "y": clientJWK.Y,
		},
	})
	require.Equal(t, http.StatusAccepted, res.StatusCode)
	state, _ := create["state"].(string)
	require.NotEmpty(t, state)

	// Alice sees the request.
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, fmt.Sprintf("https://localhost:%d/v2/api/list", testServerPort), nil)
	require.NoError(t, err)
	req.AddCookie(aliceCookie)
	resList, err := client.Do(req)
	require.NoError(t, err)
	defer closeBody(resList)
	require.Equal(t, http.StatusOK, resList.StatusCode)
	var list []map[string]any
	require.NoError(t, json.NewDecoder(resList.Body).Decode(&list))
	require.Len(t, list, 1)
	require.Equal(t, state, list[0]["state"])

	// Reject malformed response envelope from Alice.
	res, _ = doPostJSON(t, "/v2/api/confirm", map[string]any{
		"state":   state,
		"confirm": true,
		"responseEnvelope": map[string]any{
			"transportAlg": "ecdh-p256+a256gcm",
			"browserEphemeralPublicKey": map[string]any{
				"kty": "EC", "crv": "P-256",
				"x": clientJWK.X, "y": clientJWK.Y,
				"d": "forbidden",
			},
			"nonce":      base64.RawURLEncoding.EncodeToString([]byte("123456789012")),
			"ciphertext": base64.RawURLEncoding.EncodeToString([]byte("ciphertext+tag")),
		},
	}, aliceCookie)
	require.Equal(t, http.StatusBadRequest, res.StatusCode)

	// Reject response envelope with mismatched AAD binding.
	browserPriv, err := ecdh.P256().GenerateKey(rand.Reader)
	require.NoError(t, err)
	browserJWK, err := protocolv2.ECP256PublicJWKFromECDH(browserPriv.PublicKey())
	require.NoError(t, err)
	badAAD, err := json.Marshal(map[string]any{
		"v":         1,
		"state":     "wrong-state",
		"operation": "encrypt",
		"algorithm": "aes-gcm-256",
	})
	require.NoError(t, err)
	res, _ = doPostJSON(t, "/v2/api/confirm", map[string]any{
		"state":   state,
		"confirm": true,
		"responseEnvelope": map[string]any{
			"transportAlg": "ecdh-p256+a256gcm",
			"browserEphemeralPublicKey": map[string]any{
				"kty": browserJWK.Kty, "crv": browserJWK.Crv, "x": browserJWK.X, "y": browserJWK.Y,
			},
			"nonce":      base64.RawURLEncoding.EncodeToString([]byte("123456789012")),
			"ciphertext": base64.RawURLEncoding.EncodeToString([]byte("ciphertext+tag")),
			"aad":        base64.RawURLEncoding.EncodeToString(badAAD),
		},
	}, aliceCookie)
	require.Equal(t, http.StatusBadRequest, res.StatusCode)

	// Expiry path: short timeout should transition to failed/expired on result polling.
	res, create = doPostJSON(t, "/v2/request/encrypt", map[string]any{
		"targetUser": "alice",
		"keyLabel":   "expiring-key",
		"algorithm":  "aes-gcm-256",
		"value":      base64.RawURLEncoding.EncodeToString([]byte("hello")),
		"timeout":    "1s",
		"clientTransportKey": map[string]any{
			"kty": clientJWK.Kty, "crv": clientJWK.Crv, "x": clientJWK.X, "y": clientJWK.Y,
		},
	})
	require.Equal(t, http.StatusAccepted, res.StatusCode)
	expState, _ := create["state"].(string)
	require.NotEmpty(t, expState)
	time.Sleep(1500 * time.Millisecond)
	res, result := doGetJSON(t, "/v2/request/result/"+expState)
	require.Equal(t, http.StatusConflict, res.StatusCode)
	require.Equal(t, true, result["failed"])
}

func TestServerV2PlaceholderAuthDisabledByDefault(t *testing.T) {
	tmpDir := t.TempDir()
	t.Cleanup(config.SetTestConfig(map[string]any{
		"databaseDSN": tmpDir + "/v2-placeholder-disabled.db",
		"secretKey":   "dGVzdC12Mi1kYi1rZXk",
		"baseUrl":     fmt.Sprintf("https://localhost:%d", testServerPort),
		"origins":     []string{fmt.Sprintf("https://localhost:%d", testServerPort)},
	}))

	srv, cleanup := newTestServer(t, nil, nil, nil)
	require.NotNil(t, srv)
	defer cleanup()
	// Simulate WebAuthn unavailable without enabling placeholder fallback.
	srv.webAuthn = nil

	stopServerFn := startTestServer(t, srv)
	defer stopServerFn(t)
	client := clientForListener(srv.appListener)

	body := bytes.NewBufferString(`{"username":"alice","displayName":"Alice"}`)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, fmt.Sprintf("https://localhost:%d/v2/auth/register/begin", testServerPort), body)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	res, err := client.Do(req)
	require.NoError(t, err)
	defer closeBody(res)
	require.Equal(t, http.StatusServiceUnavailable, res.StatusCode)
}

func TestServerV2CreateRequestSendsWebhook(t *testing.T) {
	tmpDir := t.TempDir()
	t.Cleanup(config.SetTestConfig(map[string]any{
		"databaseDSN": tmpDir + "/v2-webhook.db",
		"secretKey":   "dGVzdC12Mi1kYi1rZXk",
		"baseUrl":     fmt.Sprintf("https://localhost:%d", testServerPort),
		"origins":     []string{fmt.Sprintf("https://localhost:%d", testServerPort)},
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

	body, err := json.Marshal(map[string]any{
		"targetUser": "alice",
		"keyLabel":   "disk-key",
		"algorithm":  "aes-gcm-256",
		"value":      base64.RawURLEncoding.EncodeToString([]byte("hello")),
		"note":       "boot unlock",
		"clientTransportKey": map[string]any{
			"kty": clientJWK.Kty, "crv": clientJWK.Crv, "x": clientJWK.X, "y": clientJWK.Y,
		},
	})
	require.NoError(t, err)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, fmt.Sprintf("https://localhost:%d/v2/request/encrypt", testServerPort), bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	res, err := client.Do(req)
	require.NoError(t, err)
	defer closeBody(res)
	require.Equal(t, http.StatusAccepted, res.StatusCode)

	select {
	case <-time.After(2 * time.Second):
		t.Fatal("did not receive webhook notification")
	case msg := <-webhookRequests:
		require.NotNil(t, msg)
		require.Equal(t, "v2", msg.Flow)
		require.Equal(t, "encrypt", msg.OperationName)
		require.Equal(t, "alice", msg.TargetUser)
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

func assertResponseError(t *testing.T, res *http.Response, expectStatusCode int, expectErr string) {
	t.Helper()

	require.Equal(t, expectStatusCode, res.StatusCode, "Response has an unexpected status code")
	require.Equal(t, jsonContentType, res.Header.Get("Content-Type"), "Content-Type header is invalid") //nolint:testifylint

	data := struct {
		Error string `json:"error"`
	}{}
	err := json.NewDecoder(res.Body).Decode(&data)
	require.NoError(t, err, "Error parsing response body as JSON")

	require.Equal(t, expectErr, data.Error, "Error message does not match")
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

// Closes a HTTP response body making sure to drain it first
// Normally invoked as a defer'd function
func closeBody(res *http.Response) {
	_, _ = io.Copy(io.Discard, res.Body)
	res.Body.Close()
}
