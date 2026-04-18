//go:build unit

package server

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/italypaleale/revaulter/pkg/config"
	"github.com/italypaleale/revaulter/pkg/protocolv2"
)

type testSigningKeyMaterial struct {
	JWK     protocolv2.ECP256SigningJWK
	JWKJSON json.RawMessage
	PEM     string
	ID      string
}

func newSigningKeyMaterial(t *testing.T) testSigningKeyMaterial {
	t.Helper()

	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	require.NoError(t, err)

	jwk, err := protocolv2.ECP256SigningJWKFromECDH(priv.PublicKey())
	require.NoError(t, err)
	jwkJSON, err := json.Marshal(jwk)
	require.NoError(t, err)

	spki, err := x509.MarshalPKIXPublicKey(priv.PublicKey())
	require.NoError(t, err)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: spki})

	id, err := jwk.ThumbprintHex()
	require.NoError(t, err)

	return testSigningKeyMaterial{
		JWK:     jwk,
		JWKJSON: jwkJSON,
		PEM:     string(pemBytes),
		ID:      id,
	}
}

func TestServerV2SigningKeyPublishAndFetch(t *testing.T) {
	tmpDir := t.TempDir()
	t.Cleanup(
		// #nosec G101 -- Hardcoded credentials are test ones
		config.SetTestConfig(map[string]any{
			"databaseDSN":     tmpDir + "/v2-signing-keys.db",
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

	aliceCookie, _ := seedV2SessionCookie(t, srv, "user-sign-1", "Alice")

	doPost := func(t *testing.T, path string, body any, cookies ...*http.Cookie) (int, http.Header, []byte) {
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
		defer res.Body.Close()
		raw, err := io.ReadAll(res.Body)
		require.NoError(t, err)
		return res.StatusCode, res.Header, raw
	}
	doGet := func(t *testing.T, path string, cookies ...*http.Cookie) (int, http.Header, []byte) {
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
		defer res.Body.Close()
		raw, err := io.ReadAll(res.Body)
		require.NoError(t, err)
		return res.StatusCode, res.Header, raw
	}

	km := newSigningKeyMaterial(t)

	// Unauthenticated publish is rejected
	status, _, _ := doPost(t, "/v2/api/signing-keys/publish", map[string]any{
		"algorithm": protocolv2.SigningAlgES256,
		"keyLabel":  "main",
		"jwk":       km.JWKJSON,
		"pem":       km.PEM,
	})
	require.Equal(t, http.StatusUnauthorized, status)

	// Successful publish
	status, _, body := doPost(t, "/v2/api/signing-keys/publish", map[string]any{
		"algorithm": protocolv2.SigningAlgES256,
		"keyLabel":  "main",
		"jwk":       km.JWKJSON,
		"pem":       km.PEM,
	}, aliceCookie)
	require.Equal(t, http.StatusOK, status, "unexpected body: %s", body)
	var pubResp map[string]any
	require.NoError(t, json.Unmarshal(body, &pubResp))
	require.Equal(t, km.ID, pubResp["id"])
	require.Equal(t, protocolv2.SigningAlgES256, pubResp["algorithm"])
	require.Equal(t, "main", pubResp["keyLabel"])

	// Republishing the same material is idempotent — same id, UPSERT semantics
	// created_at is preserved; we assert the id matches which is enough to prove the row was reused
	status, _, body = doPost(t, "/v2/api/signing-keys/publish", map[string]any{
		"algorithm": protocolv2.SigningAlgES256,
		"keyLabel":  "main",
		"jwk":       km.JWKJSON,
		"pem":       km.PEM,
	}, aliceCookie)
	require.Equal(t, http.StatusOK, status, "unexpected body: %s", body)
	require.NoError(t, json.Unmarshal(body, &pubResp))
	require.Equal(t, km.ID, pubResp["id"])

	// Unauthenticated JWK fetch works and includes required metadata
	status, header, body := doGet(t, "/v2/signing-keys/"+km.ID+".jwk")
	require.Equal(t, http.StatusOK, status, "unexpected body: %s", body)
	require.Equal(t, "public, max-age=3600", header.Get("Cache-Control"))
	var jwkResp map[string]any
	require.NoError(t, json.Unmarshal(body, &jwkResp))
	require.Equal(t, km.ID, jwkResp["id"])
	require.Equal(t, protocolv2.SigningAlgES256, jwkResp["algorithm"])
	require.Equal(t, "main", jwkResp["keyLabel"])
	require.NotZero(t, jwkResp["createdAt"])
	require.NotNil(t, jwkResp["jwk"])
	// JWK must match what was submitted
	jwkOut, err := json.Marshal(jwkResp["jwk"])
	require.NoError(t, err)
	var origJWK, returnedJWK map[string]any
	require.NoError(t, json.Unmarshal(km.JWKJSON, &origJWK))
	require.NoError(t, json.Unmarshal(jwkOut, &returnedJWK))
	require.Equal(t, origJWK, returnedJWK)

	// Unauthenticated PEM fetch returns the stored bytes verbatim as application/x-pem-file
	status, header, body = doGet(t, "/v2/signing-keys/"+km.ID+".pem")
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, "public, max-age=3600", header.Get("Cache-Control"))
	require.Contains(t, header.Get("Content-Type"), "application/x-pem-file")
	require.Equal(t, km.PEM, string(body), "PEM must be byte-for-byte the submitted PEM")

	// Unknown ids return 404 without leaking whether a user/label exists
	status, _, _ = doGet(t, "/v2/signing-keys/"+"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"+".jwk")
	require.Equal(t, http.StatusNotFound, status)
	status, _, _ = doGet(t, "/v2/signing-keys/"+"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"+".pem")
	require.Equal(t, http.StatusNotFound, status)

	// The .json alias for .jwk returns the same body as .jwk
	status, _, body = doGet(t, "/v2/signing-keys/"+km.ID+".json")
	require.Equal(t, http.StatusOK, status, "unexpected body: %s", body)
	var jsonResp map[string]any
	require.NoError(t, json.Unmarshal(body, &jsonResp))
	require.Equal(t, km.ID, jsonResp["id"])

	// Unknown extensions return 404
	status, _, _ = doGet(t, "/v2/signing-keys/"+km.ID+".xml")
	require.Equal(t, http.StatusNotFound, status)

	// No public listing endpoint (404 at the parent path)
	status, _, _ = doGet(t, "/v2/signing-keys")
	require.NotEqual(t, http.StatusOK, status)
	status, _, _ = doGet(t, "/v2/signing-keys/")
	require.NotEqual(t, http.StatusOK, status)

	// Authenticated list returns the user's keys (metadata only — no jwk/pem fields)
	status, _, body = doGet(t, "/v2/api/signing-keys", aliceCookie)
	require.Equal(t, http.StatusOK, status, "body: %s", body)
	var items []map[string]any
	require.NoError(t, json.Unmarshal(body, &items))
	require.Len(t, items, 1)
	require.Equal(t, km.ID, items[0]["id"])
	require.Equal(t, "main", items[0]["keyLabel"])
	require.Nil(t, items[0]["jwk"], "list must not include JWK bytes")
	require.Nil(t, items[0]["pem"], "list must not include PEM bytes")

	// Another user cannot unpublish Alice's key with her id
	eveCookie, _ := seedV2SessionCookie(t, srv, "user-sign-2", "Eve")
	status, _, body = doPost(t, "/v2/api/signing-keys/unpublish", map[string]any{"id": km.ID}, eveCookie)
	require.Equal(t, http.StatusOK, status)
	var unpub map[string]any
	require.NoError(t, json.Unmarshal(body, &unpub))
	require.Equal(t, false, unpub["deleted"], "Eve must not be able to delete Alice's key")

	// Key is still publicly fetchable
	status, _, _ = doGet(t, "/v2/signing-keys/"+km.ID+".jwk")
	require.Equal(t, http.StatusOK, status)

	// Alice unpublishes — hard delete removes public fetch availability
	status, _, body = doPost(t, "/v2/api/signing-keys/unpublish", map[string]any{"id": km.ID}, aliceCookie)
	require.Equal(t, http.StatusOK, status)
	require.NoError(t, json.Unmarshal(body, &unpub))
	require.Equal(t, true, unpub["deleted"])

	status, _, _ = doGet(t, "/v2/signing-keys/"+km.ID+".jwk")
	require.Equal(t, http.StatusNotFound, status)
	status, _, _ = doGet(t, "/v2/signing-keys/"+km.ID+".pem")
	require.Equal(t, http.StatusNotFound, status)
}

func TestServerV2SigningKeyPublishValidatesInputs(t *testing.T) {
	tmpDir := t.TempDir()
	t.Cleanup(
		// #nosec G101 -- Hardcoded credentials are test ones
		config.SetTestConfig(map[string]any{
			"databaseDSN":     tmpDir + "/v2-signing-keys-validate.db",
			"secretKey":       "dGVzdC12Mi1kYi1rZXk",
			"baseUrl":         fmt.Sprintf("https://localhost:%d", testServerPort),
			"webauthnOrigins": []string{fmt.Sprintf("https://localhost:%d", testServerPort)},
		}))

	srv, cleanup := newTestServer(t, nil, nil, nil)
	defer cleanup()
	stopServerFn := startTestServer(t, srv)
	defer stopServerFn(t)
	client := clientForListener(srv.appListener)

	aliceCookie, _ := seedV2SessionCookie(t, srv, "validator-user", "Alice")

	doPost := func(t *testing.T, body any) int {
		t.Helper()
		b, err := json.Marshal(body)
		require.NoError(t, err)
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, fmt.Sprintf("https://localhost:%d/v2/api/signing-keys/publish", testServerPort), bytes.NewReader(b))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(aliceCookie)
		res, err := client.Do(req)
		require.NoError(t, err)
		defer res.Body.Close()
		_, _ = io.Copy(io.Discard, res.Body)
		return res.StatusCode
	}

	km := newSigningKeyMaterial(t)

	// Unsupported algorithm rejected (only ES256 is valid in v1)
	status := doPost(t, map[string]any{"algorithm": "ES384", "keyLabel": "k", "jwk": km.JWKJSON, "pem": km.PEM})
	require.Equal(t, http.StatusBadRequest, status)

	// Missing keyLabel
	status = doPost(t, map[string]any{"algorithm": protocolv2.SigningAlgES256, "jwk": km.JWKJSON, "pem": km.PEM})
	require.Equal(t, http.StatusBadRequest, status)

	// Missing jwk
	status = doPost(t, map[string]any{"algorithm": protocolv2.SigningAlgES256, "keyLabel": "k", "pem": km.PEM})
	require.Equal(t, http.StatusBadRequest, status)

	// Missing pem
	status = doPost(t, map[string]any{"algorithm": protocolv2.SigningAlgES256, "keyLabel": "k", "jwk": km.JWKJSON})
	require.Equal(t, http.StatusBadRequest, status)

	// JWK and PEM mismatch (different key material) — rejected
	other := newSigningKeyMaterial(t)
	status = doPost(t, map[string]any{"algorithm": protocolv2.SigningAlgES256, "keyLabel": "k", "jwk": km.JWKJSON, "pem": other.PEM})
	require.Equal(t, http.StatusBadRequest, status)

	// Invalid JWK (wrong curve)
	bad := map[string]any{"kty": "EC", "crv": "P-384", "x": "aa", "y": "bb"}
	badJSON, err := json.Marshal(bad)
	require.NoError(t, err)
	status = doPost(t, map[string]any{"algorithm": protocolv2.SigningAlgES256, "keyLabel": "k", "jwk": json.RawMessage(badJSON), "pem": km.PEM})
	require.Equal(t, http.StatusBadRequest, status)

	// Long keyLabel
	longLabel := strings.Repeat("a", 130)
	status = doPost(t, map[string]any{"algorithm": protocolv2.SigningAlgES256, "keyLabel": longLabel, "jwk": km.JWKJSON, "pem": km.PEM})
	require.Equal(t, http.StatusBadRequest, status)
}

func TestServerV2SigningKeyUniqueLabelReplacesPreviousKey(t *testing.T) {
	tmpDir := t.TempDir()
	t.Cleanup(
		// #nosec G101 -- Hardcoded credentials are test ones
		config.SetTestConfig(map[string]any{
			"databaseDSN":     tmpDir + "/v2-signing-keys-replace.db",
			"secretKey":       "dGVzdC12Mi1kYi1rZXk",
			"baseUrl":         fmt.Sprintf("https://localhost:%d", testServerPort),
			"webauthnOrigins": []string{fmt.Sprintf("https://localhost:%d", testServerPort)},
		}),
	)

	srv, cleanup := newTestServer(t, nil, nil, nil)
	defer cleanup()
	stopServerFn := startTestServer(t, srv)
	defer stopServerFn(t)
	client := clientForListener(srv.appListener)

	aliceCookie, _ := seedV2SessionCookie(t, srv, "replace-user", "Alice")

	km1 := newSigningKeyMaterial(t)
	km2 := newSigningKeyMaterial(t)
	require.NotEqual(t, km1.ID, km2.ID)

	publish := func(km testSigningKeyMaterial) int {
		body, err := json.Marshal(map[string]any{
			"algorithm": protocolv2.SigningAlgES256,
			"keyLabel":  "shared",
			"jwk":       km.JWKJSON,
			"pem":       km.PEM,
		})
		require.NoError(t, err)
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, fmt.Sprintf("https://localhost:%d/v2/api/signing-keys/publish", testServerPort), bytes.NewReader(body))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(aliceCookie)
		res, err := client.Do(req)
		require.NoError(t, err)
		defer res.Body.Close()
		_, _ = io.Copy(io.Discard, res.Body)
		return res.StatusCode
	}
	getJWK := func(id string) int {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, fmt.Sprintf("https://localhost:%d/v2/signing-keys/%s.jwk", testServerPort, id), nil)
		require.NoError(t, err)
		res, err := client.Do(req)
		require.NoError(t, err)
		defer res.Body.Close()
		_, _ = io.Copy(io.Discard, res.Body)
		return res.StatusCode
	}

	// Publish two different keys under the same label — the uniqueness index on (user, algorithm, keyLabel) means only the newest id is reachable
	require.Equal(t, http.StatusOK, publish(km1))
	// Give the underlying unix-seconds clock a chance to tick so updated_at advances
	time.Sleep(1_100 * time.Millisecond)
	require.Equal(t, http.StatusOK, publish(km2))

	require.Equal(t, http.StatusNotFound, getJWK(km1.ID))
	require.Equal(t, http.StatusOK, getJWK(km2.ID))
}
