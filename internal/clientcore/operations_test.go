package clientcore

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/italypaleale/revaulter/internal/protocolv2"
)

// newTestClient returns a client that talks to the test server
func newTestClient(t *testing.T, srv *httptest.Server, requestKey string) *Client {
	t.Helper()

	client, err := NewClient(Config{
		Server:       srv.URL,
		RequestKey:   requestKey,
		HTTPClient:   srv.Client(),
		NoTrustStore: true,
	})
	require.NoError(t, err)

	return client
}

func TestClientExecuteRoundTrip(t *testing.T) {
	var createSeen atomic.Bool
	var capturedClientTransportEcdhKey protocolv2.ECP256PublicJWK
	var capturedClientTransportMlkemKey string
	state := "state-test-1"
	plainResp := []byte(`{"ok":true,"value":"hello"}`)

	// Generate a static ECDH key pair to simulate the browser user's key
	userStaticEcdhPriv, err := ecdh.P256().GenerateKey(rand.Reader)
	require.NoError(t, err)
	userStaticEcdhPubJWK, err := protocolv2.ECP256PublicJWKFromECDH(userStaticEcdhPriv.PublicKey())
	require.NoError(t, err)

	// Generate a static ML-KEM key pair to simulate the browser user's key
	userStaticMlkemDK, err := mlkem.GenerateKey768()
	require.NoError(t, err)
	userStaticMlkemPubB64 := base64.RawURLEncoding.EncodeToString(userStaticMlkemDK.EncapsulationKey().Bytes())

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/v2/request/pubkey"):
			authHeader := r.Header.Get("Authorization")
			if authHeader != "RequestKey request-key-123" {
				http.Error(w, "missing or wrong Authorization header: "+authHeader, http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			ecdhJSON, _ := json.Marshal(userStaticEcdhPubJWK)
			resp := map[string]any{
				"ecdhP256": json.RawMessage(ecdhJSON),
				"mlkem768": userStaticMlkemPubB64,
			}
			err := json.NewEncoder(w).Encode(resp)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/v2/request/encrypt"):
			authHeader := r.Header.Get("Authorization")
			if authHeader != "RequestKey request-key-123" {
				http.Error(w, "missing or wrong Authorization header: "+authHeader, http.StatusUnauthorized)
				return
			}
			defer r.Body.Close()
			createSeen.Store(true)

			var req operationRequestBody
			err := json.NewDecoder(r.Body).Decode(&req)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			if req.KeyLabel != "disk-key" || req.Algorithm != "A256GCM" || req.RequestEncAlg != protocolv2.TransportAlg {
				http.Error(w, "unexpected request fields", http.StatusBadRequest)
				return
			}
			err = req.CliEphemeralPublicKey.ValidatePublic()
			if err != nil {
				http.Error(w, "invalid cli ephemeral key: "+err.Error(), http.StatusBadRequest)
				return
			}
			if req.MlkemCiphertext == "" {
				http.Error(w, "missing mlkem ciphertext", http.StatusBadRequest)
				return
			}

			// Decrypt the E2EE payload using hybrid ECDH + ML-KEM
			cliEphPub, err := req.CliEphemeralPublicKey.ToECDHPublicKey()
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			ecdhShared, err := userStaticEcdhPriv.ECDH(cliEphPub)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			mlkemCT, err := base64.RawURLEncoding.DecodeString(req.MlkemCiphertext)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			mlkemShared, err := userStaticMlkemDK.Decapsulate(mlkemCT)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			combined := make([]byte, 0, len(ecdhShared)+len(mlkemShared))
			combined = append(combined, ecdhShared...)
			combined = append(combined, mlkemShared...)
			aesKey, err := hkdf.Key(sha256.New, combined, nil, "revaulter/v2/request-enc", 32)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			block, err := aes.NewCipher(aesKey)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			gcm, err := cipher.NewGCM(block)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			nonce, err := base64.RawURLEncoding.DecodeString(req.EncryptedPayloadNonce)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			ct, err := base64.RawURLEncoding.DecodeString(req.EncryptedPayload)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			aad := BuildRequestEncAAD("A256GCM", "disk-key", "encrypt")
			plaintext, err := gcm.Open(nil, nonce, ct, aad)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			var inner protocolv2.RequestPayloadInner
			err = json.Unmarshal(plaintext, &inner)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			err = inner.ClientTransportEcdhKey.ValidatePublic()
			if err != nil {
				http.Error(w, "invalid transport ecdh key: "+err.Error(), http.StatusBadRequest)
				return
			}
			if inner.ClientTransportMlkemKey == "" {
				http.Error(w, "missing transport mlkem key", http.StatusBadRequest)
				return
			}
			capturedClientTransportEcdhKey = inner.ClientTransportEcdhKey
			capturedClientTransportMlkemKey = inner.ClientTransportMlkemKey

			w.Header().Set("Content-Type", "application/json")
			err = json.NewEncoder(w).Encode(protocolv2.RequestResultResponse{
				State:   state,
				Pending: true,
			})
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/result/"+state):
			if !createSeen.Load() {
				http.Error(w, "create not seen yet", http.StatusInternalServerError)
				return
			}

			// ECDH key agreement for transport
			clientEcdhPub, err := capturedClientTransportEcdhKey.ToECDHPublicKey()
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			browserEcdhPriv, err := ecdh.P256().GenerateKey(rand.Reader)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			ecdhShared, err := browserEcdhPriv.ECDH(clientEcdhPub)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			// ML-KEM encapsulation for transport
			clientMlkemPubBytes, err := base64.RawURLEncoding.DecodeString(capturedClientTransportMlkemKey)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			clientMlkemPub, err := mlkem.NewEncapsulationKey768(clientMlkemPubBytes)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			mlkemShared, mlkemCT := clientMlkemPub.Encapsulate()

			// Combine secrets
			combined := make([]byte, 0, len(ecdhShared)+len(mlkemShared))
			combined = append(combined, ecdhShared...)
			combined = append(combined, mlkemShared...)
			key, err := DeriveTransportKey(combined, state)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			block, err := aes.NewCipher(key)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			aead, err := cipher.NewGCM(block)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			nonce := make([]byte, aead.NonceSize())
			_, err = rand.Read(nonce)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			aadBytes := BuildTransportAAD(state, "encrypt", "A256GCM")
			ct := aead.Seal(nil, nonce, plainResp, aadBytes)
			browserJWK, err := protocolv2.ECP256PublicJWKFromECDH(browserEcdhPriv.PublicKey())
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			err = json.NewEncoder(w).Encode(protocolv2.RequestResultResponse{
				State: state,
				Done:  true,
				ResponseEnvelope: &protocolv2.ResponseEnvelope{
					TransportAlg:              protocolv2.TransportAlg,
					BrowserEphemeralPublicKey: browserJWK,
					MlkemCiphertext:           base64.RawURLEncoding.EncodeToString(mlkemCT),
					Nonce:                     base64.RawURLEncoding.EncodeToString(nonce),
					Ciphertext:                base64.RawURLEncoding.EncodeToString(ct),
					ResultType:                "bytes",
				},
			})
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	var submittedState string
	client := newTestClient(t, srv, "request-key-123")
	res, err := client.Execute(t.Context(), Request{
		Operation: "encrypt",
		KeyLabel:  "disk-key",
		Algorithm: "A256GCM",
		Value:     base64.RawURLEncoding.EncodeToString([]byte("hello")),
		OnSubmitted: func(state string) {
			submittedState = state
		},
	})
	require.NoError(t, err)
	require.Equal(t, state, res.State)
	require.Equal(t, state, submittedState)
	require.JSONEq(t, string(plainResp), string(res.Payload))
	require.True(t, createSeen.Load())
}

func TestClientGetResultFailed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := json.NewEncoder(w).Encode(protocolv2.RequestResultResponse{
			State:  "s1",
			Failed: true,
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}))
	defer srv.Close()
	client := newTestClient(t, srv, "request-key-123")

	kp, err := NewTransportKeyPair()
	require.NoError(t, err)
	_, err = client.GetResult(t.Context(), &PendingRequest{State: "s1"}, kp, BuildTransportAAD("s1", "", "A256GCM"), 0)
	require.ErrorContains(t, err, "canceled, denied, or failed")
}

func TestClientGetResultCredential(t *testing.T) {
	tests := []struct {
		name        string
		resultToken string
		expected    string
	}{
		{
			name:        "uses the result token when the server issued one",
			resultToken: "rvr_abc",
			expected:    "ResultToken rvr_abc",
		},
		{
			name:     "falls back to the request key",
			expected: "RequestKey request-key-123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotAuth atomic.Value
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotAuth.Store(r.Header.Get("Authorization"))
				err := json.NewEncoder(w).Encode(protocolv2.RequestResultResponse{
					State:  "s1",
					Failed: true,
				})
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
			}))
			defer srv.Close()
			client := newTestClient(t, srv, "request-key-123")

			kp, err := NewTransportKeyPair()
			require.NoError(t, err)
			_, err = client.GetResult(t.Context(), &PendingRequest{State: "s1", ResultToken: tt.resultToken}, kp, BuildTransportAAD("s1", "", "A256GCM"), 0)
			require.Error(t, err)
			require.Equal(t, tt.expected, gotAuth.Load())
		})
	}
}

func TestClientOIDCToken(t *testing.T) {
	var gotUser, gotAuth atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUser.Store(r.Header.Get(protocolv2.UserIDHeader))
		gotAuth.Store(r.Header.Get("Authorization"))
		err := json.NewEncoder(w).Encode(PubkeyResponse{UserID: "other-user"})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}))
	defer srv.Close()

	const token = "eyJhbGciOiJFUzI1NiJ9.e30.c2ln"
	client, err := NewClient(Config{
		Server:       srv.URL,
		OIDCToken:    token,
		UserID:       "user-1",
		HTTPClient:   srv.Client(),
		NoTrustStore: true,
	})
	require.NoError(t, err)

	// The server returns another user's keys, which the client must refuse
	_, err = client.FetchPubkeyBundle(t.Context())
	require.ErrorContains(t, err, `public keys of user "other-user"`)
	require.Equal(t, "user-1", gotUser.Load())
	require.Equal(t, "Bearer "+token, gotAuth.Load())
}

func TestNewClientCredentials(t *testing.T) {
	const token = "eyJhbGciOiJFUzI1NiJ9.e30.c2ln"
	provider := func(context.Context) string {
		return token
	}

	tests := []struct {
		name   string
		cfg    Config
		errMsg string
	}{
		{name: "request key", cfg: Config{RequestKey: "rvk_abc"}},
		{name: "OIDC token with user ID", cfg: Config{OIDCToken: token, UserID: "user-1"}},
		{name: "OIDC token provider with user ID", cfg: Config{OIDCTokenProvider: provider, UserID: "user-1"}},
		{name: "no credential", cfg: Config{}, errMsg: "one of the properties RequestKey, OIDCToken, or OIDCTokenProvider is required"},
		{name: "request key and OIDC token", cfg: Config{RequestKey: "rvk_abc", OIDCToken: token, UserID: "user-1"}, errMsg: "mutually exclusive"},
		{name: "OIDC token and provider", cfg: Config{OIDCToken: token, OIDCTokenProvider: provider, UserID: "user-1"}, errMsg: "mutually exclusive"},
		{name: "OIDC token without user ID", cfg: Config{OIDCToken: token}, errMsg: "UserID is required"},
		{name: "OIDC token provider without user ID", cfg: Config{OIDCTokenProvider: provider}, errMsg: "UserID is required"},
		{name: "OIDC token that isn't a JWT", cfg: Config{OIDCToken: "rvk_abc", UserID: "user-1"}, errMsg: "does not contain a JWT"},
		{name: "JWT as request key", cfg: Config{RequestKey: token}, errMsg: "pass OIDC tokens in the OIDCToken property"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := tt.cfg
			cfg.Server = "https://revaulter.example.com"
			cfg.NoTrustStore = true
			_, err := NewClient(cfg)
			if tt.errMsg == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, tt.errMsg)
			}
		})
	}
}

func TestClientOIDCTokenProvider(t *testing.T) {
	var gotAuth atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth.Store(r.Header.Get("Authorization"))
		err := json.NewEncoder(w).Encode(PubkeyResponse{UserID: "user-1"})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}))
	defer srv.Close()

	// The provider returns a different token on each call, like one that refreshes an expired token
	tokens := []string{"eyJhbGciOiJFUzI1NiJ9.eyJuIjoxfQ.c2ln", "eyJhbGciOiJFUzI1NiJ9.eyJuIjoyfQ.c2ln", "", "not-a-jwt"}
	var calls atomic.Int32
	client, err := NewClient(Config{
		Server: srv.URL,
		OIDCTokenProvider: func(ctx context.Context) string {
			require.NotNil(t, ctx)
			return tokens[calls.Add(1)-1]
		},
		UserID:       "user-1",
		HTTPClient:   srv.Client(),
		NoTrustStore: true,
	})
	require.NoError(t, err)

	// The provider is invoked for every request
	_, err = client.FetchPubkeyBundle(t.Context())
	require.NoError(t, err)
	require.Equal(t, "Bearer "+tokens[0], gotAuth.Load())

	_, err = client.FetchPubkeyBundle(t.Context())
	require.NoError(t, err)
	require.Equal(t, "Bearer "+tokens[1], gotAuth.Load())

	// Invalid tokens fail the request before it's sent
	_, err = client.FetchPubkeyBundle(t.Context())
	require.ErrorContains(t, err, "empty token")
	_, err = client.FetchPubkeyBundle(t.Context())
	require.ErrorContains(t, err, "not a JWT")
	require.Equal(t, "Bearer "+tokens[1], gotAuth.Load())
	require.EqualValues(t, 4, calls.Load())
}

func TestClientGetResultStateMismatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := json.NewEncoder(w).Encode(protocolv2.RequestResultResponse{
			State: "other",
			Done:  true,
			ResponseEnvelope: &protocolv2.ResponseEnvelope{
				TransportAlg: protocolv2.TransportAlg,
				BrowserEphemeralPublicKey: protocolv2.ECP256PublicJWK{
					Kty: "EC", Crv: "P-256",
					X: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
					Y: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
				},
				MlkemCiphertext: base64.RawURLEncoding.EncodeToString(make([]byte, 1088)),
				Nonce:           base64.RawURLEncoding.EncodeToString([]byte("123456789012")),
				Ciphertext:      base64.RawURLEncoding.EncodeToString([]byte("x")),
			},
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}))
	defer srv.Close()
	client := newTestClient(t, srv, "request-key-123")

	kp, err := NewTransportKeyPair()
	require.NoError(t, err)
	_, err = client.GetResult(t.Context(), &PendingRequest{State: "expected"}, kp, BuildTransportAAD("expected", "", "A256GCM"), 0)
	require.ErrorContains(t, err, "response state mismatch")
}

// TestClientSignAndVerify exercises the full sign flow end to end:
// the client sends an encrypted digest, the simulated browser signs it with a
// freshly generated ECDSA P-256 key, the CLI decrypts the response envelope,
// and the test verifies the signature against that same public key
func TestClientSignAndVerify(t *testing.T) {
	var createSeen atomic.Bool
	var capturedClientTransportEcdhKey protocolv2.ECP256PublicJWK
	var capturedClientTransportMlkemKey string
	var capturedDigest []byte
	state := "state-sign-1"
	keyLabel := "sign-label"

	// Generate the simulated browser's derived signing key (ECDSA P-256)
	signingKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Prepare the digest the CLI will request to sign
	message := []byte("hello sign integration test")
	digest := sha256.Sum256(message)
	digestB64 := base64.RawURLEncoding.EncodeToString(digest[:])

	// Simulate the browser user's static ECDH + ML-KEM keys
	userStaticEcdhPriv, err := ecdh.P256().GenerateKey(rand.Reader)
	require.NoError(t, err)
	userStaticEcdhPubJWK, err := protocolv2.ECP256PublicJWKFromECDH(userStaticEcdhPriv.PublicKey())
	require.NoError(t, err)

	userStaticMlkemDK, err := mlkem.GenerateKey768()
	require.NoError(t, err)
	userStaticMlkemPubB64 := base64.RawURLEncoding.EncodeToString(userStaticMlkemDK.EncapsulationKey().Bytes())

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/v2/request/pubkey"):
			authHeader := r.Header.Get("Authorization")
			if authHeader != "RequestKey request-key-sign" {
				http.Error(w, "missing or wrong Authorization header: "+authHeader, http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			ecdhJSON, _ := json.Marshal(userStaticEcdhPubJWK)
			resp := map[string]any{
				"ecdhP256": json.RawMessage(ecdhJSON),
				"mlkem768": userStaticMlkemPubB64,
			}
			err := json.NewEncoder(w).Encode(resp)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/v2/request/sign"):
			authHeader := r.Header.Get("Authorization")
			if authHeader != "RequestKey request-key-sign" {
				http.Error(w, "missing or wrong Authorization header: "+authHeader, http.StatusUnauthorized)
				return
			}
			defer r.Body.Close()
			createSeen.Store(true)

			var req operationRequestBody
			err := json.NewDecoder(r.Body).Decode(&req)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			if req.KeyLabel != keyLabel || req.Algorithm != protocolv2.SigningAlgES256 || req.RequestEncAlg != protocolv2.TransportAlg {
				http.Error(w, "unexpected request fields", http.StatusBadRequest)
				return
			}
			err = req.CliEphemeralPublicKey.ValidatePublic()
			if err != nil {
				http.Error(w, "invalid cli ephemeral key: "+err.Error(), http.StatusBadRequest)
				return
			}

			cliEphPub, err := req.CliEphemeralPublicKey.ToECDHPublicKey()
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			ecdhShared, err := userStaticEcdhPriv.ECDH(cliEphPub)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			mlkemCT, err := base64.RawURLEncoding.DecodeString(req.MlkemCiphertext)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			mlkemShared, err := userStaticMlkemDK.Decapsulate(mlkemCT)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			combined := make([]byte, 0, len(ecdhShared)+len(mlkemShared))
			combined = append(combined, ecdhShared...)
			combined = append(combined, mlkemShared...)
			aesKey, err := hkdf.Key(sha256.New, combined, nil, "revaulter/v2/request-enc", 32)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			block, err := aes.NewCipher(aesKey)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			gcm, err := cipher.NewGCM(block)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			nonce, err := base64.RawURLEncoding.DecodeString(req.EncryptedPayloadNonce)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			ct, err := base64.RawURLEncoding.DecodeString(req.EncryptedPayload)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			aad := BuildRequestEncAAD(protocolv2.SigningAlgES256, keyLabel, protocolv2.OperationSign)
			plaintext, err := gcm.Open(nil, nonce, ct, aad)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			var inner protocolv2.RequestPayloadInner
			err = json.Unmarshal(plaintext, &inner)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			err = inner.ClientTransportEcdhKey.ValidatePublic()
			if err != nil {
				http.Error(w, "invalid transport ecdh key: "+err.Error(), http.StatusBadRequest)
				return
			}
			if inner.ClientTransportMlkemKey == "" {
				http.Error(w, "missing transport mlkem key", http.StatusBadRequest)
				return
			}

			// Capture the digest that the CLI asked the browser to sign
			gotDigest, err := base64.RawURLEncoding.DecodeString(inner.Value)
			if err != nil {
				http.Error(w, "invalid digest b64: "+err.Error(), http.StatusBadRequest)
				return
			}
			if len(gotDigest) != sha256.Size {
				http.Error(w, "unexpected digest length", http.StatusBadRequest)
				return
			}
			capturedDigest = gotDigest
			capturedClientTransportEcdhKey = inner.ClientTransportEcdhKey
			capturedClientTransportMlkemKey = inner.ClientTransportMlkemKey

			w.Header().Set("Content-Type", "application/json")
			err = json.NewEncoder(w).Encode(protocolv2.RequestResultResponse{
				State:   state,
				Pending: true,
			})
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/result/"+state):
			if !createSeen.Load() {
				http.Error(w, "create not seen yet", http.StatusInternalServerError)
				return
			}

			// Simulate the browser signing the digest with the derived key
			// ES256 uses r||s raw encoding (not ASN.1) — each coordinate is padded to 32 bytes
			sigR, sigS, err := ecdsa.Sign(rand.Reader, signingKey, capturedDigest)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			rs := make([]byte, 64)
			sigR.FillBytes(rs[:32])
			sigS.FillBytes(rs[32:])

			respPayload, err := json.Marshal(map[string]any{
				"state":     state,
				"operation": protocolv2.OperationSign,
				"algorithm": protocolv2.SigningAlgES256,
				"keyLabel":  keyLabel,
				"signature": base64.RawURLEncoding.EncodeToString(rs),
			})
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			// Transport encryption back to the CLI
			clientEcdhPub, err := capturedClientTransportEcdhKey.ToECDHPublicKey()
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			browserEcdhPriv, err := ecdh.P256().GenerateKey(rand.Reader)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			ecdhShared, err := browserEcdhPriv.ECDH(clientEcdhPub)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			clientMlkemPubBytes, err := base64.RawURLEncoding.DecodeString(capturedClientTransportMlkemKey)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			clientMlkemPub, err := mlkem.NewEncapsulationKey768(clientMlkemPubBytes)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			mlkemShared, mlkemCT := clientMlkemPub.Encapsulate()

			combined := make([]byte, 0, len(ecdhShared)+len(mlkemShared))
			combined = append(combined, ecdhShared...)
			combined = append(combined, mlkemShared...)
			key, err := DeriveTransportKey(combined, state)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			block, err := aes.NewCipher(key)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			aead, err := cipher.NewGCM(block)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			nonce := make([]byte, aead.NonceSize())
			_, err = rand.Read(nonce)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			aadBytes := BuildTransportAAD(state, protocolv2.OperationSign, protocolv2.SigningAlgES256)
			ct := aead.Seal(nil, nonce, respPayload, aadBytes)
			browserJWK, err := protocolv2.ECP256PublicJWKFromECDH(browserEcdhPriv.PublicKey())
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			err = json.NewEncoder(w).Encode(protocolv2.RequestResultResponse{
				State: state,
				Done:  true,
				ResponseEnvelope: &protocolv2.ResponseEnvelope{
					TransportAlg:              protocolv2.TransportAlg,
					BrowserEphemeralPublicKey: browserJWK,
					MlkemCiphertext:           base64.RawURLEncoding.EncodeToString(mlkemCT),
					Nonce:                     base64.RawURLEncoding.EncodeToString(nonce),
					Ciphertext:                base64.RawURLEncoding.EncodeToString(ct),
					ResultType:                "bytes",
				},
			})
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	client := newTestClient(t, srv, "request-key-sign")
	kp, err := NewTransportKeyPair()
	require.NoError(t, err)
	pending, err := client.CreateRequest(t.Context(), Request{
		Operation: protocolv2.OperationSign,
		KeyLabel:  keyLabel,
		Algorithm: protocolv2.SigningAlgES256,
		Value:     digestB64,
	}, kp)
	require.NoError(t, err)
	require.Equal(t, state, pending.State)

	aad := BuildTransportAAD(pending.State, protocolv2.OperationSign, protocolv2.SigningAlgES256)
	got, err := client.GetResult(t.Context(), pending, kp, aad, 0)
	require.NoError(t, err)
	require.True(t, createSeen.Load())

	// Decode the decrypted JSON envelope and verify each field
	var resp struct {
		State     string `json:"state"`
		Operation string `json:"operation"`
		Algorithm string `json:"algorithm"`
		KeyLabel  string `json:"keyLabel"`
		Signature string `json:"signature"`
	}
	err = json.Unmarshal(got, &resp)
	require.NoError(t, err)
	require.Equal(t, state, resp.State)
	require.Equal(t, protocolv2.OperationSign, resp.Operation)
	require.Equal(t, protocolv2.SigningAlgES256, resp.Algorithm)
	require.Equal(t, keyLabel, resp.KeyLabel)

	sig, err := base64.RawURLEncoding.DecodeString(resp.Signature)
	require.NoError(t, err)
	require.Len(t, sig, 64, "ES256 raw r||s must be exactly 64 bytes")

	// Verify the signature with the same public key used to sign — the whole
	// point of the test: a round-trip through the E2E encryption transport
	// must not corrupt or tamper with the signature
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	require.True(t, ecdsa.Verify(&signingKey.PublicKey, digest[:], r, s), "signature must verify against the signing public key and the original digest")

	// Sanity check: verify fails on a tampered digest
	tampered := make([]byte, len(digest))
	copy(tampered, digest[:])
	tampered[0] ^= 0xFF
	require.False(t, ecdsa.Verify(&signingKey.PublicKey, tampered, r, s), "signature must not verify against a different digest")
}

func TestClientGetResultRejectsMalformedEnvelope(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := json.NewEncoder(w).Encode(protocolv2.RequestResultResponse{
			State: "s1",
			Done:  true,
			ResponseEnvelope: &protocolv2.ResponseEnvelope{
				TransportAlg: protocolv2.TransportAlg,
				BrowserEphemeralPublicKey: protocolv2.ECP256PublicJWK{
					Kty: "EC", Crv: "P-256",
					X: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
					Y: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
					D: "forbidden",
				},
				MlkemCiphertext: base64.RawURLEncoding.EncodeToString(make([]byte, 1088)),
				Nonce:           base64.RawURLEncoding.EncodeToString([]byte("123456789012")),
				Ciphertext:      base64.RawURLEncoding.EncodeToString([]byte("x")),
			},
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}))
	defer srv.Close()
	client := newTestClient(t, srv, "request-key-123")

	kp, err := NewTransportKeyPair()
	require.NoError(t, err)
	_, err = client.GetResult(t.Context(), &PendingRequest{State: "s1"}, kp, BuildTransportAAD("s1", "", "A256GCM"), 0)
	require.Error(t, err)
}
