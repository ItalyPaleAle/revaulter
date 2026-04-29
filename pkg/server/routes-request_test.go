//go:build unit

package server

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/italypaleale/revaulter/pkg/db"
	"github.com/italypaleale/revaulter/pkg/protocolv2"
)

func newTestRequestCreateBody(t *testing.T) protocolv2.RequestCreateBody {
	t.Helper()

	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	require.NoError(t, err)

	cliJWK, err := protocolv2.ECP256PublicJWKFromECDH(priv.PublicKey())
	require.NoError(t, err)

	mlkemCiphertext := []byte{0xfb, 0xff, 0xff}
	encryptedPayloadNonce := []byte{0x01, 0x02}
	encryptedPayload := []byte{0xfb, 0xef}

	return protocolv2.RequestCreateBody{
		KeyLabel:              "disk-key",
		Algorithm:             "A256GCM",
		Note:                  "ticket 42 / primary",
		RequestEncAlg:         protocolv2.TransportAlg,
		CliEphemeralPublicKey: cliJWK,
		MlkemCiphertext:       base64.StdEncoding.EncodeToString(mlkemCiphertext),
		EncryptedPayloadNonce: base64.StdEncoding.EncodeToString(encryptedPayloadNonce),
		EncryptedPayload:      base64.StdEncoding.EncodeToString(encryptedPayload),
	}
}

func TestValidateV2CreateBodyValidEncryptNormalizesBase64(t *testing.T) {
	body := newTestRequestCreateBody(t)

	err := validateV2CreateBody(protocolv2.OperationEncrypt, &body)
	require.NoError(t, err)
	assert.Equal(t, base64.RawURLEncoding.EncodeToString([]byte{0xfb, 0xff, 0xff}), body.MlkemCiphertext)
	assert.Equal(t, base64.RawURLEncoding.EncodeToString([]byte{0x01, 0x02}), body.EncryptedPayloadNonce)
	assert.Equal(t, base64.RawURLEncoding.EncodeToString([]byte{0xfb, 0xef}), body.EncryptedPayload)
}

func TestValidateV2CreateBodyValidSign(t *testing.T) {
	body := newTestRequestCreateBody(t)
	body.Algorithm = protocolv2.SigningAlgES256

	err := validateV2CreateBody(protocolv2.OperationSign, &body)
	require.NoError(t, err)
}

func TestValidateV2CreateBodyAcceptedEncryptionAlgorithms(t *testing.T) {
	// Both the JOSE-style and long-form names are accepted on encrypt/decrypt, case-insensitive
	algorithms := []string{
		"A256GCM",
		"a256gcm",
		"aes-256-gcm",
		"AES-256-GCM",
		"aes256gcm",
		"C20P",
		"c20p",
		"chacha20-poly1305",
		"ChaCha20-Poly1305",
		"chacha20poly1305",
	}
	ops := []string{protocolv2.OperationEncrypt, protocolv2.OperationDecrypt}

	for _, op := range ops {
		for _, alg := range algorithms {
			t.Run(op+"/"+alg, func(t *testing.T) {
				body := newTestRequestCreateBody(t)
				body.Algorithm = alg
				err := validateV2CreateBody(op, &body)
				require.NoError(t, err)
			})
		}
	}
}

func TestValidateV2CreateBodyRejectsUnknownEncryptionAlgorithm(t *testing.T) {
	for _, op := range []string{protocolv2.OperationEncrypt, protocolv2.OperationDecrypt} {
		t.Run(op, func(t *testing.T) {
			body := newTestRequestCreateBody(t)
			body.Algorithm = "rsa-oaep"
			err := validateV2CreateBody(op, &body)
			require.EqualError(t, err, `unsupported encryption algorithm "rsa-oaep"`)
		})
	}
}

func TestValidateV2CreateBodyRejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name       string
		op         string
		mutateBody func(*protocolv2.RequestCreateBody)
		wantErr    string
	}{
		{
			name:    "invalid operation",
			op:      "rotate",
			wantErr: "Invalid operation",
		},
		{
			name: "missing key label",
			op:   protocolv2.OperationEncrypt,
			mutateBody: func(body *protocolv2.RequestCreateBody) {
				body.KeyLabel = ""
			},
			wantErr: "missing parameter 'keyLabel'",
		},
		{
			name: "key label too long",
			op:   protocolv2.OperationEncrypt,
			mutateBody: func(body *protocolv2.RequestCreateBody) {
				body.KeyLabel = strings.Repeat("k", protocolv2.MaxKeyLabelLength+1)
			},
			wantErr: "parameter 'keyLabel' must be 1-24 bytes and contain only [A-Za-z0-9_.+-]",
		},
		{
			name: "key label has invalid characters",
			op:   protocolv2.OperationEncrypt,
			mutateBody: func(body *protocolv2.RequestCreateBody) {
				body.KeyLabel = "bad label"
			},
			wantErr: "parameter 'keyLabel' must be 1-24 bytes and contain only [A-Za-z0-9_.+-]",
		},
		{
			name: "missing algorithm",
			op:   protocolv2.OperationEncrypt,
			mutateBody: func(body *protocolv2.RequestCreateBody) {
				body.Algorithm = ""
			},
			wantErr: "missing parameter 'algorithm'",
		},
		{
			name: "algorithm too long",
			op:   protocolv2.OperationEncrypt,
			mutateBody: func(body *protocolv2.RequestCreateBody) {
				body.Algorithm = strings.Repeat("a", 65)
			},
			wantErr: "parameter 'algorithm' cannot be longer than 64 characters",
		},
		{
			name: "unsupported signing algorithm",
			op:   protocolv2.OperationSign,
			mutateBody: func(body *protocolv2.RequestCreateBody) {
				body.Algorithm = "HS256"
			},
			wantErr: `unsupported signing algorithm "HS256"`,
		},
		{
			name: "note has invalid characters",
			op:   protocolv2.OperationEncrypt,
			mutateBody: func(body *protocolv2.RequestCreateBody) {
				body.Note = "bad\nnote"
			},
			wantErr: "parameter 'note' contains invalid characters",
		},
		{
			name: "note too long",
			op:   protocolv2.OperationEncrypt,
			mutateBody: func(body *protocolv2.RequestCreateBody) {
				body.Note = strings.Repeat("n", 41)
			},
			wantErr: "parameter 'note' cannot be longer than 40 characters",
		},
		{
			name: "unsupported request encryption algorithm",
			op:   protocolv2.OperationEncrypt,
			mutateBody: func(body *protocolv2.RequestCreateBody) {
				body.RequestEncAlg = "rsa-oaep"
			},
			wantErr: "unsupported requestEncAlg",
		},
		{
			name: "invalid cli ephemeral public key",
			op:   protocolv2.OperationEncrypt,
			mutateBody: func(body *protocolv2.RequestCreateBody) {
				body.CliEphemeralPublicKey.Kty = "RSA"
			},
			wantErr: `invalid cliEphemeralPublicKey: invalid JWK 'kty': "RSA"`,
		},
		{
			name: "empty mlkem ciphertext",
			op:   protocolv2.OperationEncrypt,
			mutateBody: func(body *protocolv2.RequestCreateBody) {
				body.MlkemCiphertext = ""
			},
			wantErr: "mlkemCiphertext is empty or invalid",
		},
		{
			name: "malformed mlkem ciphertext",
			op:   protocolv2.OperationEncrypt,
			mutateBody: func(body *protocolv2.RequestCreateBody) {
				body.MlkemCiphertext = "***"
			},
			wantErr: "mlkemCiphertext is empty or invalid",
		},
		{
			name: "empty encrypted payload nonce",
			op:   protocolv2.OperationEncrypt,
			mutateBody: func(body *protocolv2.RequestCreateBody) {
				body.EncryptedPayloadNonce = ""
			},
			wantErr: "encryptedPayloadNonce is empty or invalid",
		},
		{
			name: "malformed encrypted payload nonce",
			op:   protocolv2.OperationEncrypt,
			mutateBody: func(body *protocolv2.RequestCreateBody) {
				body.EncryptedPayloadNonce = "***"
			},
			wantErr: "encryptedPayloadNonce is empty or invalid",
		},
		{
			name: "empty encrypted payload",
			op:   protocolv2.OperationEncrypt,
			mutateBody: func(body *protocolv2.RequestCreateBody) {
				body.EncryptedPayload = ""
			},
			wantErr: "encryptedPayload is empty or invalid",
		},
		{
			name: "malformed encrypted payload",
			op:   protocolv2.OperationEncrypt,
			mutateBody: func(body *protocolv2.RequestCreateBody) {
				body.EncryptedPayload = "***"
			},
			wantErr: "encryptedPayload is empty or invalid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := newTestRequestCreateBody(t)
			if tt.mutateBody != nil {
				tt.mutateBody(&body)
			}

			err := validateV2CreateBody(tt.op, &body)
			require.EqualError(t, err, tt.wantErr)
		})
	}
}

// TestServerV2RequestResultContextCancelClearsSubscription verifies that when the long-poll's request context is canceled, the handler unsubscribes itself
func TestServerV2RequestResultContextCancelClearsSubscription(t *testing.T) {
	setTestConfig(t, "v2-result-ctx-cancel.db")

	srv := newTestServer(t, nil, nil, nil)
	require.NotNil(t, srv)

	startTestServer(t, srv)
	client := clientForListener(srv.appListener)

	_, aliceUser := seedV2SessionCookie(t, srv, "user-alice", "Alice")

	const state = "state-result-ctx-cancel"
	rs := srv.db.RequestStore()
	now := time.Now().UTC().Truncate(time.Second)
	err := rs.CreateRequest(t.Context(), db.CreateRequestInput{
		State:            state,
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

	// Issue a long-poll with a cancelable context so we can simulate the caller disconnecting
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	url := fmt.Sprintf("https://localhost:%d/v2/request/result/%s", testServerPort, state)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+aliceUser.RequestKey)

	type pollResult struct {
		res *http.Response
		err error
	}
	resCh := make(chan pollResult, 1)
	go func() {
		// Body is closed below
		//nolint:bodyclose
		res, dErr := client.Do(req)
		resCh <- pollResult{res: res, err: dErr}
	}()

	// Wait for the subscription to be registered before canceling
	require.Eventually(t, func() bool {
		srv.lock.RLock()
		defer srv.lock.RUnlock()
		_, ok := srv.subs[state]
		return ok
	}, 2*time.Second, 5*time.Millisecond, "subscription was not registered")

	// Cancel the request context
	cancel()

	// The client receives an error because the connection was aborted; either way the handler must have returned and the subscription must be cleared
	select {
	case r := <-resCh:
		if r.res != nil {
			_, _ = io.Copy(io.Discard, r.res.Body)
			r.res.Body.Close()
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for the long-poll to return after context cancel")
	}

	require.Eventually(t, func() bool {
		srv.lock.RLock()
		defer srv.lock.RUnlock()
		_, ok := srv.subs[state]
		return !ok
	}, 2*time.Second, 5*time.Millisecond, "subscription was not removed after context cancel")
}

// TestServerV2RequestResultSecondSubscriberEvictsFirst verifies that opening a second long-poll for the same state evicts the first one
// The first caller must return a 202 pending response, and after the request transitions to terminal only the second caller receives the result
func TestServerV2RequestResultSecondSubscriberEvictsFirst(t *testing.T) {
	setTestConfig(t, "v2-result-evict.db")

	srv := newTestServer(t, nil, nil, nil)
	require.NotNil(t, srv)

	startTestServer(t, srv)
	client := clientForListener(srv.appListener)

	_, aliceUser := seedV2SessionCookie(t, srv, "user-alice", "Alice")

	const state = "state-result-evict"
	rs := srv.db.RequestStore()
	now := time.Now().UTC().Truncate(time.Second)
	err := rs.CreateRequest(t.Context(), db.CreateRequestInput{
		State:            state,
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

	type pollResult struct {
		status int
		body   map[string]any
		err    error
	}
	startPoll := func() <-chan pollResult {
		ch := make(chan pollResult, 1)
		go func() {
			url := fmt.Sprintf("https://localhost:%d/v2/request/result/%s", testServerPort, state)
			req, rErr := http.NewRequestWithContext(t.Context(), http.MethodGet, url, nil)
			if rErr != nil {
				ch <- pollResult{err: rErr}
				return
			}

			req.Header.Set("Authorization", "Bearer "+aliceUser.RequestKey)

			res, dErr := client.Do(req)
			if dErr != nil {
				ch <- pollResult{err: dErr}
				return
			}
			defer func() {
				_, _ = io.Copy(io.Discard, res.Body)
				res.Body.Close()
			}()

			var body map[string]any
			_ = json.NewDecoder(res.Body).Decode(&body)
			ch <- pollResult{status: res.StatusCode, body: body}
		}()
		return ch
	}

	waitForSub := func(prev chan struct{}) chan struct{} {
		t.Helper()
		var ch chan struct{}
		require.Eventually(t, func() bool {
			srv.lock.RLock()
			defer srv.lock.RUnlock()
			ch = srv.subs[state]
			return ch != nil && ch != prev
		}, 2*time.Second, 5*time.Millisecond, "expected new subscription channel")
		return ch
	}

	// Subscriber #1 starts the long-poll; capture its watch channel via the server's subscription map
	sub1 := startPoll()
	ch1 := waitForSub(nil)

	// Subscriber #2 starts and must replace subscriber #1 in the map
	sub2 := startPoll()
	ch2 := waitForSub(ch1)
	require.NotEqual(t, ch1, ch2, "second subscription must replace the first")

	// The first subscriber's channel must already be closed by subscribeState
	select {
	case _, ok := <-ch1:
		require.False(t, ok, "evicted channel must be closed without a value")
	case <-time.After(time.Second):
		t.Fatal("evicted channel was not closed by subscribeState")
	}

	// Subscriber #1 must promptly return 202 pending — its subscription is gone, so it cannot receive the result
	select {
	case r := <-sub1:
		require.NoError(t, r.err)
		require.Equal(t, http.StatusAccepted, r.status)
		require.Equal(t, true, r.body["pending"])
	case <-time.After(2 * time.Second):
		t.Fatal("evicted subscriber #1 did not return")
	}

	// Subscriber #2 should still be active in the subscription map; verify it is the same channel we captured
	srv.lock.RLock()
	current := srv.subs[state]
	srv.lock.RUnlock()
	require.Equal(t, ch2, current, "subscriber #2 must remain the active subscription")

	// Drive the request to a terminal state (cancel) and notify subscribers
	// We bypass the API confirm endpoint to avoid coupling this test to CSRF / session details
	rec, err := rs.CancelRequest(t.Context(), state, aliceUser.ID)
	require.NoError(t, err)
	require.NotNil(t, rec)

	srv.lock.Lock()
	srv.notifySubscriber(state)
	srv.lock.Unlock()

	// Subscriber #2 receives the terminal response
	select {
	case r := <-sub2:
		require.NoError(t, r.err)
		require.Equal(t, http.StatusConflict, r.status)
		require.Equal(t, true, r.body["failed"])
	case <-time.After(2 * time.Second):
		t.Fatal("subscriber #2 did not receive the terminal response")
	}

	// The response is consumed; any further long-poll for the same state must be unable to read it
	url := fmt.Sprintf("https://localhost:%d/v2/request/result/%s", testServerPort, state)
	extraReq, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, nil)
	require.NoError(t, err)

	extraReq.Header.Set("Authorization", "Bearer "+aliceUser.RequestKey)

	extraRes, err := client.Do(extraReq)
	require.NoError(t, err)
	defer func() {
		_, _ = io.Copy(io.Discard, extraRes.Body)
		extraRes.Body.Close()
	}()

	require.Equal(t, http.StatusNotFound, extraRes.StatusCode)
}
