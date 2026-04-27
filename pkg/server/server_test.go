package server

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
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
	"maps"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"

	"github.com/italypaleale/revaulter/pkg/config"
	"github.com/italypaleale/revaulter/pkg/db"
	"github.com/italypaleale/revaulter/pkg/protocolv2"
	"github.com/italypaleale/revaulter/pkg/utils/bufconn"
	"github.com/italypaleale/revaulter/pkg/utils/webhook"
)

const (
	testServerPort = 5701
	bufconnBufSize = 1 << 20 // 1MB
)

// doRequestKeyJSON sends an HTTP request to /v2/request/<suffix> with the request key in the Authorization header
// The helper drains and closes the response body before returning, but the bodyclose linter can't see through the wrapper, so callers add `//nolint:bodyclose`
func doRequestKeyJSON(t *testing.T, client *http.Client, method, suffix, requestKey string, body any) (*http.Response, map[string]any) {
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
	req.Header.Set("Authorization", "Bearer "+requestKey)

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

func TestMain(m *testing.M) {
	// #nosec G101 -- Hardcoded credentials are test ones
	_ = config.SetTestConfig(map[string]any{
		"logLevel":       "info",
		"port":           testServerPort,
		"bind":           "127.0.0.1",
		"sessionTimeout": 5 * time.Minute,
		"requestTimeout": 5 * time.Minute,
		"webhookUrl":     "http://test.local",
		"databaseDSN":    ":memory:",
		"secretKey":      "dGVzdC12Mi1kYi1rZXk",
	})

	gin.SetMode(gin.ReleaseMode)
	os.Exit(m.Run())
}

func TestServerV2RequestLifecycle(t *testing.T) {
	setTestConfig(t, "v2-req.db")

	srv := newTestServer(t, nil, nil, nil)
	require.NotNil(t, srv)

	startTestServer(t, srv)
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
	res, createResp := doRequestKeyJSON(t, client, http.MethodPost, "encrypt", aliceUser.RequestKey, newV2CreateRequestBody("disk-key", "A256GCM", clientJWK))
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
	res, result := doRequestKeyJSON(t, client, http.MethodGet, "result/"+state, aliceUser.RequestKey, nil)
	require.Equal(t, http.StatusOK, res.StatusCode)
	require.Equal(t, state, result["state"])
	require.Equal(t, true, result["done"])
	_, ok = result["responseEnvelope"].(map[string]any)
	require.True(t, ok)

	res, result = doRequestKeyJSON(t, client, http.MethodGet, "result/"+state, aliceUser.RequestKey, nil)
	require.Equal(t, http.StatusNotFound, res.StatusCode)
	require.Contains(t, result["error"], "State not found or expired")
}

func TestServerV2PublicSignup(t *testing.T) {
	setTestConfig(t, "v2-users.db")

	srv := newTestServer(t, nil, nil, nil)
	require.NotNil(t, srv)

	startTestServer(t, srv)
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

func TestServerV2SessionMiddlewareAllowsNonreadyUsersOnListAPI(t *testing.T) {
	setTestConfig(t, "v2-nonready.db")

	srv := newTestServer(t, nil, nil, nil)
	require.NotNil(t, srv)

	startTestServer(t, srv)
	client := clientForListener(srv.appListener)

	sessionCookie, _ := seedV2SessionCookie(t, srv, "user-nonready", "Non-ready")
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, fmt.Sprintf("https://localhost:%d/v2/api/list", testServerPort), nil)
	require.NoError(t, err)
	req.AddCookie(sessionCookie)

	res, err := client.Do(req)
	require.NoError(t, err)
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		res.Body.Close()
	}()

	var body []map[string]any
	require.NoError(t, json.NewDecoder(res.Body).Decode(&body))
	require.Equal(t, http.StatusOK, res.StatusCode)
	require.Empty(t, body)
}

func TestServerV2APIListScopesToSignedInUser(t *testing.T) {
	setTestConfig(t, "v2-list-scope.db")

	srv := newTestServer(t, nil, nil, nil)
	require.NotNil(t, srv)

	startTestServer(t, srv)
	client := clientForListener(srv.appListener)

	aliceCookie, aliceUser := seedV2SessionCookie(t, srv, "user-alice-list", "Alice")
	bobCookie, bobUser := seedV2SessionCookie(t, srv, "user-bob-list", "Bob")

	clientPriv, err := ecdh.P256().GenerateKey(rand.Reader)
	require.NoError(t, err)
	clientJWK, err := protocolv2.ECP256PublicJWKFromECDH(clientPriv.PublicKey())
	require.NoError(t, err)

	// Create a pending request on the given user's request-key endpoint and return the state
	// The handler is API-to-server, so no session cookie is required
	createRequest := func(t *testing.T, user *db.User, label string) string {
		t.Helper()
		// Body is drained and closed inside doRequestKeyJSON; the linter can't follow the wrapper
		//nolint:bodyclose
		res, out := doRequestKeyJSON(t, client, http.MethodPost, "encrypt", user.RequestKey, newV2CreateRequestBody(label, "A256GCM", clientJWK))
		require.Equal(t, http.StatusAccepted, res.StatusCode)
		state, _ := out["state"].(string)
		require.NotEmpty(t, state)
		return state
	}

	listRequests := func(t *testing.T, cookie *http.Cookie) (int, []map[string]any) {
		t.Helper()
		req, rErr := http.NewRequestWithContext(
			t.Context(),
			http.MethodGet,
			fmt.Sprintf("https://localhost:%d/v2/api/list", testServerPort),
			nil,
		)
		require.NoError(t, rErr)
		if cookie != nil {
			req.AddCookie(cookie)
		}
		res, dErr := client.Do(req)
		require.NoError(t, dErr)
		defer func() {
			_, _ = io.Copy(io.Discard, res.Body)
			res.Body.Close()
		}()
		if res.StatusCode != http.StatusOK {
			return res.StatusCode, nil
		}
		var out []map[string]any
		require.NoError(t, json.NewDecoder(res.Body).Decode(&out))
		return res.StatusCode, out
	}

	aliceState1 := createRequest(t, aliceUser, "alice-key-1")
	aliceState2 := createRequest(t, aliceUser, "alice-key-2")
	bobState := createRequest(t, bobUser, "bob-key")

	// Alice's list returns only her requests
	status, aliceList := listRequests(t, aliceCookie)
	require.Equal(t, http.StatusOK, status)
	require.Len(t, aliceList, 2)
	seen := make([]string, 0, len(aliceList))
	for _, item := range aliceList {
		require.Equal(t, aliceUser.ID, item["userId"])
		state, _ := item["state"].(string)
		require.NotEqual(t, bobState, state, "Bob's state must not appear in Alice's list")
		seen = append(seen, state)
	}
	require.ElementsMatch(t, []string{aliceState1, aliceState2}, seen)

	// Bob's list returns only his single request
	status, bobList := listRequests(t, bobCookie)
	require.Equal(t, http.StatusOK, status)
	require.Len(t, bobList, 1)
	require.Equal(t, bobUser.ID, bobList[0]["userId"])
	require.Equal(t, bobState, bobList[0]["state"])

	// Unauthenticated requests are rejected before the handler reads the store
	status, _ = listRequests(t, nil)
	require.Equal(t, http.StatusUnauthorized, status)
}

// openListStream opens /v2/api/list with Accept: application/x-ndjson and returns the response together with a channel that delivers each ndjson line
// Callers must defer the returned cleanup to close the body and cancel the request context
func openListStream(t *testing.T, client *http.Client, cookie *http.Cookie) (*http.Response, <-chan string) {
	t.Helper()

	ctx, cancel := context.WithCancel(t.Context())
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		fmt.Sprintf("https://localhost:%d/v2/api/list", testServerPort),
		nil,
	)
	require.NoError(t, err)
	req.Header.Set("Accept", ndJSONContentType)
	if cookie != nil {
		req.AddCookie(cookie)
	}

	res, err := client.Do(req)
	require.NoError(t, err)

	lines := make(chan string, 8)
	go func() {
		defer close(lines)
		scanner := bufio.NewScanner(res.Body)
		scanner.Buffer(make([]byte, 64*1024), 1024*1024)
		for scanner.Scan() {
			lines <- scanner.Text()
		}
	}()

	t.Cleanup(func() {
		cancel()
		_ = res.Body.Close()
	})
	return res, lines
}

func TestServerV2APIListStreamUnauthenticated(t *testing.T) {
	setTestConfig(t, "v2-list-stream-unauth.db")

	srv := newTestServer(t, nil, nil, nil)
	require.NotNil(t, srv)

	startTestServer(t, srv)
	client := clientForListener(srv.appListener)

	// Note stream is closed with a cleanup function
	//nolint:bodyclose
	res, _ := openListStream(t, client, nil)
	require.Equal(t, http.StatusUnauthorized, res.StatusCode)
}

func TestServerV2APIListStreamEmptySendsSentinel(t *testing.T) {
	setTestConfig(t, "v2-list-stream-empty.db")

	srv := newTestServer(t, nil, nil, nil)
	require.NotNil(t, srv)

	startTestServer(t, srv)
	client := clientForListener(srv.appListener)

	aliceCookie, _ := seedV2SessionCookie(t, srv, "user-alice-stream-empty", "Alice")

	// Note stream is closed with a cleanup function
	//nolint:bodyclose
	res, lines := openListStream(t, client, aliceCookie)
	require.Equal(t, http.StatusOK, res.StatusCode)
	require.Contains(t, res.Header.Get("Content-Type"), ndJSONContentType)

	// When the initial list is empty the handler writes a single `{}` sentinel line before entering the event loop
	select {
	case line, ok := <-lines:
		require.True(t, ok, "stream closed before delivering sentinel")
		require.Equal(t, "{}", line)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for empty-list sentinel")
	}
}

func TestServerV2APIListStreamScopesToSignedInUser(t *testing.T) {
	setTestConfig(t, "v2-list-stream-scope.db")

	srv := newTestServer(t, nil, nil, nil)
	require.NotNil(t, srv)
	rs := srv.db.RequestStore()

	startTestServer(t, srv)
	client := clientForListener(srv.appListener)

	aliceCookie, aliceUser := seedV2SessionCookie(t, srv, "user-alice-stream", "Alice")
	_, bobUser := seedV2SessionCookie(t, srv, "user-bob-stream", "Bob")

	// Seed one pending request for each user directly against the store so the test doesn't depend on the encrypt endpoint
	now := time.Now().UTC().Truncate(time.Second)
	err := rs.CreateRequest(t.Context(), db.CreateRequestInput{
		State:            "alice-stream-state",
		UserID:           aliceUser.ID,
		Operation:        "encrypt",
		RequestorIP:      "127.0.0.1",
		KeyLabel:         "alice-key",
		Algorithm:        "A256GCM",
		CreatedAt:        now,
		ExpiresAt:        now.Add(10 * time.Minute),
		EncryptedRequest: `{}`,
	})
	require.NoError(t, err)

	err = rs.CreateRequest(t.Context(), db.CreateRequestInput{
		State:            "bob-stream-state",
		UserID:           bobUser.ID,
		Operation:        "encrypt",
		RequestorIP:      "127.0.0.1",
		KeyLabel:         "bob-key",
		Algorithm:        "A256GCM",
		CreatedAt:        now,
		ExpiresAt:        now.Add(10 * time.Minute),
		EncryptedRequest: `{}`,
	})
	require.NoError(t, err)

	// Open the stream
	// Note stream is closed with a cleanup function
	//nolint:bodyclose
	res, lines := openListStream(t, client, aliceCookie)
	require.Equal(t, http.StatusOK, res.StatusCode)
	require.Contains(t, res.Header.Get("Content-Type"), ndJSONContentType)

	readLine := func(t *testing.T, timeout time.Duration) string {
		t.Helper()
		select {
		case line, ok := <-lines:
			require.True(t, ok, "stream closed while waiting for a line")
			return line
		case <-time.After(timeout):
			t.Fatal("timed out waiting for stream line")
			return ""
		}
	}

	// Initial batch must contain only Alice's pending request
	initial := readLine(t, 2*time.Second)
	var item map[string]any
	require.NoError(t, json.Unmarshal([]byte(initial), &item))
	require.Equal(t, "alice-stream-state", item["state"])
	require.Equal(t, aliceUser.ID, item["userId"])

	// No Bob rows must follow in the initial batch
	select {
	case extra, ok := <-lines:
		if ok {
			t.Fatalf("unexpected extra row in initial batch: %s", extra)
		}
	case <-time.After(300 * time.Millisecond):
		// expected — initial batch exhausted
	}

	// Reading the initial line proves the handler has already Subscribe()'d and Flush()'d, so any publish after this point is observable
	// A pubsub event targeting a different user must be filtered out by the UserID check in the handler
	srv.publishListItem(&db.V2RequestListItem{
		State:  "bob-live-update",
		Status: "removed",
		UserID: bobUser.ID,
	})
	select {
	case leaked := <-lines:
		t.Fatalf("Alice received a message targeting Bob: %s", leaked)
	case <-time.After(400 * time.Millisecond):
		// expected — filtered
	}

	// A pubsub event targeting Alice must be delivered within a couple of flush ticks
	srv.publishListItem(&db.V2RequestListItem{
		State:  "alice-live-update",
		Status: "removed",
		UserID: aliceUser.ID,
	})
	live := readLine(t, 2*time.Second)
	require.NoError(t, json.Unmarshal([]byte(live), &item))
	require.Equal(t, "alice-live-update", item["state"])
	require.Equal(t, aliceUser.ID, item["userId"])
}

func TestServerV2APIListStreamSuppressesDuplicateInitialEvents(t *testing.T) {
	setTestConfig(t, "v2-list-stream-dup.db")

	srv := newTestServer(t, nil, nil, nil)
	require.NotNil(t, srv)
	rs := srv.db.RequestStore()

	startTestServer(t, srv)
	client := clientForListener(srv.appListener)

	aliceCookie, aliceUser := seedV2SessionCookie(t, srv, "user-alice-stream-dup", "Alice")
	now := time.Now().UTC().Truncate(time.Second)
	err := rs.CreateRequest(t.Context(), db.CreateRequestInput{
		State:            "alice-stream-dup-state",
		UserID:           aliceUser.ID,
		Operation:        "encrypt",
		RequestorIP:      "127.0.0.1",
		KeyLabel:         "alice-key",
		Algorithm:        "A256GCM",
		CreatedAt:        now,
		ExpiresAt:        now.Add(10 * time.Minute),
		EncryptedRequest: `{}`,
	})
	require.NoError(t, err)

	// Note stream is closed with a cleanup function
	//nolint:bodyclose
	res, lines := openListStream(t, client, aliceCookie)
	require.Equal(t, http.StatusOK, res.StatusCode)

	select {
	case line, ok := <-lines:
		require.True(t, ok, "stream closed before delivering initial item")
		var item map[string]any
		require.NoError(t, json.Unmarshal([]byte(line), &item))
		require.Equal(t, "alice-stream-dup-state", item["state"])
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for initial stream item")
	}

	// A live publish for a state already replayed by the initial list should not duplicate the item
	srv.publishListItem(&db.V2RequestListItem{
		State:  "alice-stream-dup-state",
		Status: string(db.V2RequestStatusPending),
		UserID: aliceUser.ID,
	})
	select {
	case dup, ok := <-lines:
		if ok {
			t.Fatalf("unexpected duplicate stream row: %s", dup)
		}
	case <-time.After(400 * time.Millisecond):
		// Expected because duplicate pending item was suppressed
	}

	// Removal events for an initial state must still be delivered so the UI can clear the item
	srv.publishListItem(&db.V2RequestListItem{
		State:  "alice-stream-dup-state",
		Status: "removed",
		UserID: aliceUser.ID,
	})
	select {
	case line, ok := <-lines:
		require.True(t, ok, "stream closed before delivering removal")
		var item map[string]any
		require.NoError(t, json.Unmarshal([]byte(line), &item))
		require.Equal(t, "alice-stream-dup-state", item["state"])
		require.Equal(t, "removed", item["status"])
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for removal stream item")
	}
}

func TestServerV2FinalizeSignupRefreshesSessionForReadyAPI(t *testing.T) {
	setTestConfig(t, "v2-finalize-refresh.db")

	srv := newTestServer(t, nil, nil, nil)
	require.NotNil(t, srv)

	startTestServer(t, srv)
	client := clientForListener(srv.appListener)

	sessionCookie, user := seedV2SessionCookie(t, srv, "user-finalize-refresh", "Refresh User")

	requestEncPriv, err := ecdh.P256().GenerateKey(rand.Reader)
	require.NoError(t, err)
	requestEncJWK, err := protocolv2.ECP256PublicJWKFromECDH(requestEncPriv.PublicKey())
	require.NoError(t, err)
	requestEncJWKJSON, err := json.Marshal(requestEncJWK)
	require.NoError(t, err)

	body, err := json.Marshal(map[string]any{
		"requestEncEcdhPubkey":         json.RawMessage(requestEncJWKJSON),
		"requestEncMlkemPubkey":        base64.RawURLEncoding.EncodeToString([]byte("test-mlkem-pubkey-refresh")),
		"anchorEs384PublicKey":         map[string]any{},
		"anchorMldsa87PublicKey":       "test-anchor-ml-dsa",
		"pubkeyBundleSignatureEs384":   "sig-es384",
		"pubkeyBundleSignatureMldsa87": "sig-mldsa87",
		"wrappedAnchorKey":             base64.RawURLEncoding.EncodeToString([]byte("wrapped-anchor-refresh")),
		"attestationPayload":           `{"userId":"user-finalize-refresh","credentialId":"cred-user-finalize-refresh","credentialPublicKeyHash":"test","wrappedKeyEpoch":1,"createdAt":1}`,
		"attestationSignatureEs384":    "sig-es384",
		"attestationSignatureMldsa87":  "sig-mldsa87",
	})
	require.NoError(t, err)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, fmt.Sprintf("https://localhost:%d/v2/auth/finalize-signup", testServerPort), bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(sessionCookie)
	res, err := client.Do(req)
	require.NoError(t, err)
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		res.Body.Close()
	}()
	require.Equal(t, http.StatusBadRequest, res.StatusCode)
	_ = user
}

func TestServerV2SessionEndpointAllowsNonreadyUsers(t *testing.T) {
	setTestConfig(t, "v2-session-nonready.db")

	srv := newTestServer(t, nil, nil, nil)
	require.NotNil(t, srv)

	startTestServer(t, srv)
	client := clientForListener(srv.appListener)

	sessionCookie, _ := seedV2SessionCookie(t, srv, "user-nonready-session", "Nonready Session")
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
	require.Equal(t, "user-nonready-session", body["userId"])
}

func TestServerV2DisableSignup(t *testing.T) {
	setTestConfig(t, "v2-disable-signup.db", map[string]any{"disableSignup": true})

	srv := newTestServer(t, nil, nil, nil)
	require.NotNil(t, srv)

	startTestServer(t, srv)
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
	setTestConfig(t, "v2-security.db")

	srv := newTestServer(t, nil, nil, nil)
	require.NotNil(t, srv)

	startTestServer(t, srv)
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
	aliceCookie, aliceUser := seedV2SessionCookie(t, srv, "user-alice", "Alice")

	clientPriv, err := ecdh.P256().GenerateKey(rand.Reader)
	require.NoError(t, err)
	clientJWK, err := protocolv2.ECP256PublicJWKFromECDH(clientPriv.PublicKey())
	require.NoError(t, err)

	// Reject malformed client transport JWK (private material present).
	invalidCreateBody := newV2CreateRequestBody("disk-key", "A256GCM", clientJWK)
	invalidCreateBody["cliEphemeralPublicKey"] = map[string]any{
		"kty": "EC", "crv": "P-256",
		"x": clientJWK.X, "y": clientJWK.Y,
		"d": "forbidden",
	}
	res, _ := doRequestKeyJSON(t, client, http.MethodPost, "encrypt", aliceUser.RequestKey, invalidCreateBody)
	require.Equal(t, http.StatusBadRequest, res.StatusCode)

	invalidNoteBody := newV2CreateRequestBody("disk-key", "A256GCM", clientJWK)
	invalidNoteBody["note"] = "boot unlock!"
	res, _ = doRequestKeyJSON(t, client, http.MethodPost, "encrypt", aliceUser.RequestKey, invalidNoteBody)
	require.Equal(t, http.StatusBadRequest, res.StatusCode)

	// Create a valid request targeted to alice.
	res, create := doRequestKeyJSON(t, client, http.MethodPost, "encrypt", aliceUser.RequestKey, newV2CreateRequestBody("disk-key", "A256GCM", clientJWK))
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
	expiringCreateBody := newV2CreateRequestBody("expiring-key", "A256GCM", clientJWK)
	expiringCreateBody["timeout"] = "1s"
	res, create = doRequestKeyJSON(t, client, http.MethodPost, "encrypt", aliceUser.RequestKey, expiringCreateBody)
	require.Equal(t, http.StatusAccepted, res.StatusCode)
	expState, _ := create["state"].(string)
	require.NotEmpty(t, expState)
	time.Sleep(1_500 * time.Millisecond)
	res, result := doRequestKeyJSON(t, client, http.MethodGet, "result/"+expState, aliceUser.RequestKey, nil)
	require.Equal(t, http.StatusConflict, res.StatusCode)
	require.Equal(t, true, result["failed"])

	res, result = doRequestKeyJSON(t, client, http.MethodGet, "result/"+expState, aliceUser.RequestKey, nil)
	require.Equal(t, http.StatusNotFound, res.StatusCode)
	require.Contains(t, result["error"], "State not found or expired")
}

func TestServerV2CreateRequestSendsWebhook(t *testing.T) {
	setTestConfig(t, "v2-webhook.db")

	webhookRequests := make(chan *webhook.WebhookRequest, 1)
	srv := newTestServer(t, &mockWebhook{requests: webhookRequests}, nil, nil)
	require.NotNil(t, srv)
	startTestServer(t, srv)
	client := clientForListener(srv.appListener)

	clientPriv, err := ecdh.P256().GenerateKey(rand.Reader)
	require.NoError(t, err)
	clientJWK, err := protocolv2.ECP256PublicJWKFromECDH(clientPriv.PublicKey())
	require.NoError(t, err)

	_, aliceUser := seedV2SessionCookie(t, srv, "user-alice", "Alice")

	createBody := newV2CreateRequestBody("disk-key", "A256GCM", clientJWK)
	createBody["note"] = "boot unlock"
	body, err := json.Marshal(createBody)
	require.NoError(t, err)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, fmt.Sprintf("https://localhost:%d/v2/request/encrypt", testServerPort), bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+aliceUser.RequestKey)
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
		require.Equal(t, "A256GCM", msg.Algorithm)
		require.Equal(t, "boot unlock", msg.Note)
	}
}

func TestServerExecuteRequestExpiryEventExpiresAndSchedulesDeletion(t *testing.T) {
	setTestConfig(t, "v2-expiry-callback.db")

	srv := newTestServer(t, nil, nil, nil)
	require.NotNil(t, srv)
	rs := srv.db.RequestStore()

	_, user := seedV2SessionCookie(t, srv, "user-expiry-callback", "Expiry Callback")
	now := time.Now().UTC().Truncate(time.Second)
	err := rs.CreateRequest(t.Context(), db.CreateRequestInput{
		State:            "state-expiry-callback",
		UserID:           user.ID,
		Operation:        "encrypt",
		RequestorIP:      "127.0.0.1",
		KeyLabel:         "callback-key",
		Algorithm:        "A256GCM",
		CreatedAt:        now.Add(-2 * time.Minute),
		ExpiresAt:        now.Add(-1 * time.Minute),
		EncryptedRequest: `{"cliEphemeralPublicKey":{"kty":"EC","crv":"P-256","x":"test","y":"test"},"nonce":"bm9uY2U","ciphertext":"Y3Q"}`,
	})
	require.NoError(t, err)

	srv.executeRequestExpiryEvent(requestExpiryEvent{
		State:  "state-expiry-callback",
		UserID: user.ID,
		TTL:    now.Add(-1 * time.Minute),
	})

	rec, err := rs.GetRequest(t.Context(), "state-expiry-callback")
	require.NoError(t, err)
	require.NotNil(t, rec)
	require.Equal(t, db.V2RequestStatusExpired, rec.Status)

	srv.executeDeleteEvent(deleteEvent{
		KeyName: "request-delete:state-expiry-callback",
		Kind:    "request",
		ID:      "state-expiry-callback",
		TTL:     now.Add(10 * time.Minute),
	})

	rec, err = rs.GetRequest(t.Context(), "state-expiry-callback")
	require.NoError(t, err)
	require.Nil(t, rec)
}

func TestServerV2AuthLogoutDeletesSessionImmediately(t *testing.T) {
	setTestConfig(t, "v2-logout.db")

	srv := newTestServer(t, nil, nil, nil)
	require.NotNil(t, srv)

	startTestServer(t, srv)
	client := clientForListener(srv.appListener)

	sessionCookie, _ := seedV2SessionCookie(t, srv, "user-logout", "Logout User")
	require.NotEmpty(t, sessionCookie.Value)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, fmt.Sprintf("https://localhost:%d/v2/auth/logout", testServerPort), bytes.NewReader([]byte(`{}`)))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(sessionCookie)

	res, err := client.Do(req)
	require.NoError(t, err)
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		res.Body.Close()
	}()
	require.Equal(t, http.StatusOK, res.StatusCode)

	req2, err := http.NewRequestWithContext(t.Context(), http.MethodGet, fmt.Sprintf("https://localhost:%d/v2/auth/session", testServerPort), nil)
	require.NoError(t, err)
	resCookies := res.Cookies()
	for _, cookie := range resCookies {
		if cookie.Name == sessionCookie.Name {
			req2.AddCookie(cookie)
		}
	}
	res2, err := client.Do(req2)
	require.NoError(t, err)
	defer func() {
		_, _ = io.Copy(io.Discard, res2.Body)
		res2.Body.Close()
	}()
	require.Equal(t, http.StatusUnauthorized, res2.StatusCode)
}

func TestServerV2AuthLogoutClearsBothCookieNames(t *testing.T) {
	// Regression: logout must clear both the `__Host-_s` (secure) and `_s` (insecure) cookie names
	// A scheme change between login and logout (e.g. a proxy switching https→http on a subsequent hop) would otherwise leave a stray session cookie behind
	setTestConfig(t, "v2-logout-both.db")

	srv := newTestServer(t, nil, nil, nil)
	require.NotNil(t, srv)

	startTestServer(t, srv)
	client := clientForListener(srv.appListener)

	sessionCookie, _ := seedV2SessionCookie(t, srv, "user-logout-both", "Logout Both User")
	require.NotEmpty(t, sessionCookie.Value)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, fmt.Sprintf("https://localhost:%d/v2/auth/logout", testServerPort), bytes.NewReader([]byte(`{}`)))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(sessionCookie)

	res, err := client.Do(req)
	require.NoError(t, err)
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		res.Body.Close()
	}()
	require.Equal(t, http.StatusOK, res.StatusCode)

	var sawSecure, sawInsecure bool
	for _, cookie := range res.Cookies() {
		switch cookie.Name {
		case sessionCookieNameSecure:
			sawSecure = true
			require.Equal(t, "/", cookie.Path, "secure cookie must be cleared with path=/")
			require.True(t, cookie.MaxAge < 0 || !cookie.Expires.IsZero() && cookie.Expires.Before(time.Now()), "secure cookie must be expired")
		case sessionCookieNameInsecure:
			sawInsecure = true
			require.Equal(t, "/v2", cookie.Path, "insecure cookie must be cleared with path=/v2")
			require.True(t, cookie.MaxAge < 0 || !cookie.Expires.IsZero() && cookie.Expires.Before(time.Now()), "insecure cookie must be expired")
		}
	}
	require.True(t, sawSecure, "logout must set an expired __Host-_s cookie")
	require.True(t, sawInsecure, "logout must set an expired _s cookie")
}

func newTestServer(t *testing.T, wh *mockWebhook, httpClientTransport http.RoundTripper, logDest io.Writer) *Server {
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

	t.Cleanup(
		config.SetTestConfig(map[string]any{
			"tLSCertPEM": cert,
			"tLSKeyPEM":  key,
		}),
	)
	dbConn := db.NewTestDatabaseForServerTests(t)
	err = db.RunMigrations(t.Context(), dbConn, log)
	require.NoError(t, err)

	srv, err := NewServer(NewServerOpts{
		Log:     log,
		Webhook: wh,
		DB:      dbConn,
	})
	require.NoError(t, err)

	srv.appListener = bufconn.Listen(bufconnBufSize)

	if httpClientTransport != nil {
		srv.httpClient.Transport = httpClientTransport
	}

	return srv
}

// setTestConfig applies the standard v2 server test config, registering cleanup with t
// dbName is joined to t.TempDir() and used for databaseDSN
// Optional override maps are merged on top of the defaults, so callers can toggle extra flags (e.g. "disableSignup": true)
func setTestConfig(t *testing.T, dbName string, overrides ...map[string]any) {
	t.Helper()

	tmpDir := t.TempDir()
	cfg := map[string]any{
		"databaseDSN": tmpDir + "/" + dbName,
		// #nosec G101 -- Hardcoded credentials are test ones
		"secretKey":       "dGVzdC12Mi1kYi1rZXk",
		"baseUrl":         fmt.Sprintf("https://localhost:%d", testServerPort),
		"webauthnOrigins": []string{fmt.Sprintf("https://localhost:%d", testServerPort)},
	}

	// Add overrides
	for _, o := range overrides {
		maps.Copy(cfg, o)
	}

	// Set the test config and enable automated cleanup on test end
	t.Cleanup(config.SetTestConfig(cfg))
}

func seedV2SessionCookie(t *testing.T, srv *Server, userID string, displayName string) (*http.Cookie, *db.User) {
	t.Helper()

	user, _ := db.ExecuteInTransaction(t.Context(), srv.db, 30*time.Second, func(ctx context.Context, tx *db.DbTx) (*db.User, error) {
		as := tx.AuthStore()

		_, err := as.RegisterUser(ctx, db.RegisterUserInput{
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
		_, err = as.FinalizeSignup(
			ctx,
			db.FinalizeSignupInput{
				UserID:                userID,
				WrappedPrimaryKey:     "test-wrapped-primary-key",
				RequestEncEcdhPubkey:  string(requestEncJWKJSON),
				RequestEncMlkemPubkey: base64.RawURLEncoding.EncodeToString([]byte("test-mlkem-pubkey")),
			},
		)
		require.NoError(t, err)

		user, err := as.GetUserByID(ctx, userID)
		require.NoError(t, err)
		require.NotNil(t, user)

		return user, nil
	})

	signed, err := newAuthSessionToken(user, config.Get().SessionTimeout)
	require.NoError(t, err)
	token, err := signAuthSessionToken(signed)
	require.NoError(t, err)

	return &http.Cookie{
		Name:  sessionCookieNameSecure,
		Value: token,
		Path:  "/",
	}, user
}

// testAnchorKeyPair holds the private halves of a hybrid anchor pair plus the wire-format pubkeys that match what FinalizeSignup stores
// Used by tests that need to forge anchor-signed proofs (publication, attestation, ...) for an existing user
type testAnchorKeyPair struct {
	Es384Priv        *ecdsa.PrivateKey
	Mldsa87Priv      *mldsa87.PrivateKey
	Mldsa87Pub       *mldsa87.PublicKey
	Mldsa87PubBytes  []byte
	Es384JWKBody     string
	Mldsa87PubBase64 string
}

// seedV2AnchorForUser provisions a hybrid anchor pair on an existing user (already created via seedV2SessionCookie)
// Returns the priv keys so tests can sign publication or attestation proofs against the pinned anchor
func seedV2AnchorForUser(t *testing.T, srv *Server, userID string) *testAnchorKeyPair {
	t.Helper()

	esPriv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	mlPub, mlPriv, err := mldsa87.GenerateKey(rand.Reader)
	require.NoError(t, err)
	mlPubBytes, err := mlPub.MarshalBinary()
	require.NoError(t, err)

	es384JWK, err := protocolv2.ECP384PublicJWKFromECDSA(&esPriv.PublicKey)
	require.NoError(t, err)
	es384Body := es384JWK.CanonicalBody()
	mlPubB64 := base64.RawURLEncoding.EncodeToString(mlPubBytes)

	// Update the user record directly so tests can layer an anchor on top of seedV2SessionCookie without rerunning the full signup flow
	_, err = srv.db.Exec(t.Context(),
		`UPDATE v2_users SET anchor_es384_public_key = $1, anchor_mldsa87_public_key = $2 WHERE id = $3`,
		es384Body, mlPubB64, userID,
	)
	require.NoError(t, err)

	return &testAnchorKeyPair{
		Es384Priv:        esPriv,
		Mldsa87Priv:      mlPriv,
		Mldsa87Pub:       mlPub,
		Mldsa87PubBytes:  mlPubBytes,
		Es384JWKBody:     es384Body,
		Mldsa87PubBase64: mlPubB64,
	}
}

// buildSigningKeyPublicationProof assembles a payload at server-now and signs it under the supplied anchor
// Tests pass in the user ID, algorithm, key label, JWK thumbprint id, and current epoch — the server's verifier will compare each against its own copy
func buildSigningKeyPublicationProof(t *testing.T, anchor *testAnchorKeyPair, userID, algorithm, keyLabel, keyID string, epoch int64) (payload, sigEsB64, sigMlB64 string) {
	t.Helper()

	return signSigningKeyPublication(t, anchor, &protocolv2.SigningKeyPublicationPayload{
		UserID:          userID,
		Algorithm:       algorithm,
		KeyLabel:        keyLabel,
		KeyID:           keyID,
		WrappedKeyEpoch: epoch,
		CreatedAt:       time.Now().Unix(),
		V:               protocolv2.SigningKeyPublicationVersion,
	})
}

// signSigningKeyPublication produces canonical-body + base64url ES384 + base64url ML-DSA-87 signatures for a publication payload
// Tests use this to assemble a proof that the server's verifier will accept
func signSigningKeyPublication(t *testing.T, anchor *testAnchorKeyPair, payload *protocolv2.SigningKeyPublicationPayload) (canonicalBody, sigEsB64, sigMlB64 string) {
	t.Helper()

	canonicalBody = payload.CanonicalBody()
	msg := protocolv2.CanonicalSigningKeyPublicationMessage(payload)

	digest := sha512.Sum384(msg)
	r, s, err := ecdsa.Sign(rand.Reader, anchor.Es384Priv, digest[:])
	require.NoError(t, err)
	sig := make([]byte, protocolv2.ES384SignatureSize)
	const half = protocolv2.ES384SignatureSize / 2
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(sig[half-len(rBytes):half], rBytes)
	copy(sig[protocolv2.ES384SignatureSize-len(sBytes):], sBytes)
	sigEsB64 = base64.RawURLEncoding.EncodeToString(sig)

	mlSig := make([]byte, protocolv2.MLDSA87SignatureSize)
	err = mldsa87.SignTo(anchor.Mldsa87Priv, msg, nil, false, mlSig)
	require.NoError(t, err)
	sigMlB64 = base64.RawURLEncoding.EncodeToString(mlSig)

	return canonicalBody, sigEsB64, sigMlB64
}

func startTestServer(t *testing.T, srv *Server) {
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

	// Tear down the test server when test is done
	t.Cleanup(func() {
		// Shutdown the server
		srvCancel()

		// At the end of the test, there should be no error
		require.NoError(t, <-startErrCh, "received an unexpected error in startErrCh")
	})
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
		"requestEncAlg": protocolv2.TransportAlg,
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
		"transportAlg": protocolv2.TransportAlg,
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

// testValidWrappedAnchorEnvelope returns a syntactically valid wrapped-anchor envelope for tests
// The envelope is the one enforced by validateWrappedAnchorEnvelope: alphabetical newline `key=value` lines wrapped in base64url
// The ciphertext is not a real AES-GCM output; these tests exercise route-level structural validation, not decryption
func testValidWrappedAnchorEnvelope(t *testing.T) string {
	t.Helper()
	ciphertext := base64.RawURLEncoding.EncodeToString([]byte("test-ciphertext"))
	nonce := base64.RawURLEncoding.EncodeToString(make([]byte, 12))
	body := "ciphertext=" + ciphertext + "\nnonce=" + nonce + "\nv=1"
	return base64.RawURLEncoding.EncodeToString([]byte(body))
}

func TestServerV2UpdateDisplayName(t *testing.T) {
	setTestConfig(t, "v2-display-name.db")

	srv := newTestServer(t, nil, nil, nil)
	require.NotNil(t, srv)

	startTestServer(t, srv)
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

	sessionCookie, _ := seedV2SessionCookie(t, srv, "user-alice", "Alice")

	// Successful update
	res, body := doPostJSON(t, "/v2/auth/update-display-name", map[string]any{"displayName": "New Name"}, sessionCookie)
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		res.Body.Close()
	}()
	require.Equal(t, http.StatusOK, res.StatusCode)
	require.Equal(t, true, body["ok"])
	require.Equal(t, "New Name", body["displayName"])

	// Verify via session endpoint
	res, body = doGetJSON(t, "/v2/auth/session", sessionCookie)
	require.Equal(t, http.StatusOK, res.StatusCode)
	require.Equal(t, "New Name", body["displayName"])

	// Too-long name
	longName := strings.Repeat("a", 101)
	res, _ = doPostJSON(t, "/v2/auth/update-display-name", map[string]any{"displayName": longName}, sessionCookie)
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		res.Body.Close()
	}()
	require.Equal(t, http.StatusBadRequest, res.StatusCode)

	// Without session cookie — 401
	res, _ = doPostJSON(t, "/v2/auth/update-display-name", map[string]any{"displayName": "Test"})
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		res.Body.Close()
	}()
	require.Equal(t, http.StatusUnauthorized, res.StatusCode)
}

func TestServerV2UpdateWrappedKey(t *testing.T) {
	setTestConfig(t, "v2-wrapped-key.db")

	srv := newTestServer(t, nil, nil, nil)
	require.NotNil(t, srv)
	as := srv.db.AuthStore()

	startTestServer(t, srv)
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

	sessionCookie, _ := seedV2SessionCookie(t, srv, "user-alice", "Alice")

	// The wrapped primary key lives on the credential that authenticated the session, so the route requires its credential_id
	const credentialID = "cred-user-alice"

	// The update route validates the wrapped-anchor envelope structurally, so tests must send something that passes validation
	validAnchor := testValidWrappedAnchorEnvelope(t)

	// Successful update
	res, body := doPostJSON(t, "/v2/auth/update-wrapped-key", map[string]any{"credentialId": credentialID, "wrappedPrimaryKey": "new-key-blob", "wrappedAnchorKey": validAnchor, "advanceEpoch": true}, sessionCookie)
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		res.Body.Close()
	}()
	require.Equal(t, http.StatusOK, res.StatusCode)
	require.Equal(t, true, body["ok"])
	user, err := as.GetUserByID(t.Context(), "user-alice")
	require.NoError(t, err)
	require.EqualValues(t, 2, user.WrappedKeyEpoch)

	// Empty string is valid
	res, body = doPostJSON(t, "/v2/auth/update-wrapped-key", map[string]any{"credentialId": credentialID, "wrappedPrimaryKey": "", "wrappedAnchorKey": ""}, sessionCookie)
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		res.Body.Close()
	}()
	require.Equal(t, http.StatusOK, res.StatusCode)
	require.Equal(t, true, body["ok"])
	user, err = as.GetUserByID(t.Context(), "user-alice")
	require.NoError(t, err)
	require.EqualValues(t, 2, user.WrappedKeyEpoch)

	// Starting an add-credential WebAuthn ceremony must block concurrent password changes
	_, err = db.ExecuteInTransaction(t.Context(), srv.db, 20*time.Second, func(ctx context.Context, tx *db.DbTx) (any, error) {
		return tx.AuthStore().BeginChallenge(ctx, "add-credential", "user-alice", "pending-add", time.Now().UTC().Add(5*time.Minute), nil)
	})
	require.NoError(t, err)

	res, body = doPostJSON(t, "/v2/auth/update-wrapped-key", map[string]any{"credentialId": credentialID, "wrappedPrimaryKey": "blocked-while-pending", "wrappedAnchorKey": validAnchor, "advanceEpoch": true}, sessionCookie)
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		res.Body.Close()
	}()
	require.Equal(t, http.StatusConflict, res.StatusCode)
	require.Contains(t, body["error"], "passkey registration is in progress")
}

func TestServerV2CredentialLifecycle(t *testing.T) {
	setTestConfig(t, "v2-cred-lifecycle.db")

	srv := newTestServer(t, nil, nil, nil)
	require.NotNil(t, srv)

	startTestServer(t, srv)
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

	doGetJSONArray := func(t *testing.T, path string, cookies ...*http.Cookie) (*http.Response, []map[string]any) {
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
		var out []map[string]any
		_ = json.NewDecoder(res.Body).Decode(&out)
		return res, out
	}

	sessionCookie, _ := seedV2SessionCookie(t, srv, "user-alice", "Alice")

	// List credentials — should have 1
	res, creds := doGetJSONArray(t, "/v2/auth/credentials", sessionCookie)
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		res.Body.Close()
	}()
	require.Equal(t, http.StatusOK, res.StatusCode)
	require.Len(t, creds, 1)
	credID, _ := creds[0]["id"].(string)
	require.NotEmpty(t, credID)

	// Rename credential
	res2, body := doPostJSON(t, "/v2/auth/credentials/rename", map[string]any{
		"id":          credID,
		"displayName": "My Passkey",
	}, sessionCookie)
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		res.Body.Close()
	}()
	require.Equal(t, http.StatusOK, res2.StatusCode)
	require.Equal(t, true, body["ok"])

	// Verify rename
	res, creds = doGetJSONArray(t, "/v2/auth/credentials", sessionCookie)
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		res.Body.Close()
	}()
	require.Equal(t, http.StatusOK, res.StatusCode)
	require.Equal(t, "My Passkey", creds[0]["displayName"])

	// Delete last credential — should fail with 409
	res2, _ = doPostJSON(t, "/v2/auth/credentials/delete", map[string]any{"id": credID}, sessionCookie)
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		res2.Body.Close()
	}()
	require.Equal(t, http.StatusConflict, res2.StatusCode)

	// Delete nonexistent credential — 404
	res2, _ = doPostJSON(t, "/v2/auth/credentials/delete", map[string]any{"id": "nonexistent"}, sessionCookie)
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		res2.Body.Close()
	}()
	require.Equal(t, http.StatusNotFound, res2.StatusCode)
}
