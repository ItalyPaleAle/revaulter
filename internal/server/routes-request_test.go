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

	"github.com/italypaleale/revaulter/internal/protocolv2"
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
				body.Note = strings.Repeat("n", protocolv2.MaxNoteLength+1)
			},
			wantErr: "parameter 'note' cannot be longer than 80 characters",
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
		{
			name: "encrypted payload too large",
			op:   protocolv2.OperationEncrypt,
			mutateBody: func(body *protocolv2.RequestCreateBody) {
				body.EncryptedPayload = base64.RawURLEncoding.EncodeToString(make([]byte, protocolv2.MaxEnvelopeCiphertextSize+1))
			},
			wantErr: "encryptedPayload cannot be larger than 300 KB",
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

func TestValidateEnvelopeCiphertextSize(t *testing.T) {
	err := validateEnvelopeCiphertextSize("responseEnvelope", base64.RawURLEncoding.EncodeToString(make([]byte, protocolv2.MaxEnvelopeCiphertextSize)))
	require.NoError(t, err)

	err = validateEnvelopeCiphertextSize("responseEnvelope", base64.RawURLEncoding.EncodeToString(make([]byte, protocolv2.MaxEnvelopeCiphertextSize+1)))
	require.EqualError(t, err, "Invalid responseEnvelope: ciphertext cannot be larger than 300 KB")
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
	seedTestRequest(t, srv, aliceUser.ID, state, time.Now().Add(10*time.Minute))

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

	// Wait for the waiter to be registered before canceling
	require.Eventually(t, func() bool {
		rec := getTestRequest(t, srv, aliceUser.ID, state)
		return rec != nil && rec.Waiter != ""
	}, 2*time.Second, 5*time.Millisecond, "waiter was not registered")

	// Cancel the request context
	cancel()

	// The client receives an error because the connection was aborted; either way the handler must have returned and the waiter must be cleared
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
		rec := getTestRequest(t, srv, aliceUser.ID, state)
		return rec != nil && rec.Waiter == ""
	}, 2*time.Second, 5*time.Millisecond, "waiter was not removed after context cancel")
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
	seedTestRequest(t, srv, aliceUser.ID, state, time.Now().Add(10*time.Minute))

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

	waitForWaiter := func(prev string) string {
		t.Helper()
		var waiter string
		require.Eventually(t, func() bool {
			rec := getTestRequest(t, srv, aliceUser.ID, state)
			if rec == nil {
				return false
			}
			waiter = rec.Waiter
			return waiter != "" && waiter != prev
		}, 2*time.Second, 5*time.Millisecond, "expected a new waiter")
		return waiter
	}

	// Subscriber #1 starts the long-poll; capture its waiter token from the user's actor
	sub1 := startPoll()
	waiter1 := waitForWaiter("")

	// Subscriber #2 starts and must replace subscriber #1
	sub2 := startPoll()
	waiter2 := waitForWaiter(waiter1)
	require.NotEqual(t, waiter1, waiter2, "second subscription must replace the first")

	// Subscriber #1 must promptly return 202 pending — it was evicted, so it cannot receive the result
	select {
	case r := <-sub1:
		require.NoError(t, r.err)
		require.Equal(t, http.StatusAccepted, r.status)
		require.Equal(t, true, r.body["pending"])
	case <-time.After(2 * time.Second):
		t.Fatal("evicted subscriber #1 did not return")
	}

	// Subscriber #2 should still be the active waiter, even after subscriber #1 returned
	rec := getTestRequest(t, srv, aliceUser.ID, state)
	require.NotNil(t, rec)
	require.Equal(t, waiter2, rec.Waiter, "subscriber #2 must remain the active waiter")

	// Drive the request to a terminal state (cancel), which wakes the waiter
	// We bypass the API confirm endpoint to avoid coupling this test to CSRF / session details
	res, err := invokeUserActor[userChangeRes](t.Context(), srv, aliceUser.ID, userMethodCancel, userChangeReq{State: state})
	require.NoError(t, err)
	require.Empty(t, res.Error)

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
