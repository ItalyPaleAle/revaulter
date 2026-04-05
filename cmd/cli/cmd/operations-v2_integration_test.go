package cmd

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"

	"github.com/italypaleale/revaulter/pkg/protocolv2"
)

type testV2Flags struct {
	server string
	body   []byte
	alg    string
}

func (f *testV2Flags) BindToCommand(_ *cobra.Command) {}
func (f *testV2Flags) Validate() error                { return nil }
func (f *testV2Flags) RequestBody(clientTransportKey protocolv2.ECP256PublicJWK) ([]byte, error) {
	var req v2OperationRequest
	if err := json.Unmarshal(f.body, &req); err != nil {
		return nil, err
	}
	req.ClientTransportKey = clientTransportKey
	return json.Marshal(req)
}
func (f *testV2Flags) GetServer() string                  { return f.server }
func (f *testV2Flags) GetRequestKey() string              { return "" }
func (f *testV2Flags) GetAlgorithm() string               { return f.alg }
func (f *testV2Flags) GetConnectionOptions() (bool, bool) { return false, false }

func TestV2OperationCmdCreateAndDecryptResult(t *testing.T) {
	var createSeen atomic.Bool
	var capturedReq v2OperationRequest
	state := "state-test-1"
	plainResp := []byte(`{"ok":true,"value":"hello"}`)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/v2/request/encrypt"):
			defer r.Body.Close()
			createSeen.Store(true)

			require.NoError(t, json.NewDecoder(r.Body).Decode(&capturedReq))
			require.Equal(t, "alice", capturedReq.TargetUser)
			require.Equal(t, "disk-key", capturedReq.KeyLabel)
			require.Equal(t, "aes-gcm-256", capturedReq.Algorithm)
			require.NoError(t, capturedReq.ClientTransportKey.ValidatePublic())

			w.Header().Set("Content-Type", "application/json")
			require.NoError(t, json.NewEncoder(w).Encode(protocolv2.RequestResultResponse{
				State:   state,
				Pending: true,
			}))
			return

		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/v2/request/result/"+state):
			require.True(t, createSeen.Load())
			clientPub, err := capturedReq.ClientTransportKey.ToECDHPublicKey()
			require.NoError(t, err)
			browserPriv, err := ecdh.P256().GenerateKey(rand.Reader)
			require.NoError(t, err)
			shared, err := browserPriv.ECDH(clientPub)
			require.NoError(t, err)
			key, err := deriveV2TransportKey(shared, state)
			require.NoError(t, err)

			block, err := aes.NewCipher(key)
			require.NoError(t, err)
			aead, err := cipher.NewGCM(block)
			require.NoError(t, err)
			nonce := make([]byte, aead.NonceSize())
			_, err = rand.Read(nonce)
			require.NoError(t, err)
			aad := buildTransportAAD(state, "encrypt", "aes-gcm-256")
			ct := aead.Seal(nil, nonce, plainResp, aad)
			browserJWK, err := protocolv2.ECP256PublicJWKFromECDH(browserPriv.PublicKey())
			require.NoError(t, err)

			w.Header().Set("Content-Type", "application/json")
			require.NoError(t, json.NewEncoder(w).Encode(protocolv2.RequestResultResponse{
				State: state,
				Done:  true,
				ResponseEnvelope: &protocolv2.ResponseEnvelope{
					TransportAlg:              "ecdh-p256+a256gcm",
					BrowserEphemeralPublicKey: browserJWK,
					Nonce:                     base64.RawURLEncoding.EncodeToString(nonce),
					Ciphertext:                base64.RawURLEncoding.EncodeToString(ct),
					ResultType:                "bytes",
				},
			}))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	flagsBody, err := json.Marshal(v2OperationRequest{
		TargetUser: "alice",
		KeyLabel:   "disk-key",
		Algorithm:  "aes-gcm-256",
		Value:      base64.RawURLEncoding.EncodeToString([]byte("hello")),
	})
	require.NoError(t, err)

	impl := &v2OperationCmd{
		Operation: "encrypt",
		flags: &testV2Flags{
			server: srv.URL,
			body:   flagsBody,
			alg:    "aes-gcm-256",
		},
	}
	kp, err := newV2TransportKeyPair()
	require.NoError(t, err)
	gotState, err := impl.createRequest(context.Background(), srv.Client(), kp.Public)
	require.NoError(t, err)
	require.Equal(t, state, gotState)
	got, err := impl.getResult(context.Background(), srv.Client(), gotState, kp.Private, buildTransportAAD(gotState, "encrypt", "aes-gcm-256"))
	require.NoError(t, err)
	require.JSONEq(t, string(plainResp), string(got))
	require.True(t, createSeen.Load())
}

func TestV2OperationCmdGetResultFailed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, json.NewEncoder(w).Encode(protocolv2.RequestResultResponse{
			State:  "s1",
			Failed: true,
		}))
	}))
	defer srv.Close()
	impl := &v2OperationCmd{flags: &testV2Flags{server: srv.URL, body: []byte(`{}`), alg: "aes-gcm-256"}}

	clientPriv, err := ecdh.P256().GenerateKey(rand.Reader)
	require.NoError(t, err)
	_, err = impl.getResult(context.Background(), srv.Client(), "s1", clientPriv, buildTransportAAD("s1", "", "aes-gcm-256"))
	require.ErrorContains(t, err, "canceled, denied, or failed")
}

func TestV2OperationCmdGetResultStateMismatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, json.NewEncoder(w).Encode(protocolv2.RequestResultResponse{
			State: "other",
			Done:  true,
			ResponseEnvelope: &protocolv2.ResponseEnvelope{
				TransportAlg: "ecdh-p256+a256gcm",
				BrowserEphemeralPublicKey: protocolv2.ECP256PublicJWK{
					Kty: "EC", Crv: "P-256",
					X: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
					Y: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
				},
				Nonce:      base64.RawURLEncoding.EncodeToString([]byte("123456789012")),
				Ciphertext: base64.RawURLEncoding.EncodeToString([]byte("x")),
			},
		}))
	}))
	defer srv.Close()
	impl := &v2OperationCmd{flags: &testV2Flags{server: srv.URL, body: []byte(`{}`), alg: "aes-gcm-256"}}

	clientPriv, err := ecdh.P256().GenerateKey(rand.Reader)
	require.NoError(t, err)
	_, err = impl.getResult(context.Background(), srv.Client(), "expected", clientPriv, buildTransportAAD("expected", "", "aes-gcm-256"))
	require.ErrorContains(t, err, "response state mismatch")
}

func TestV2OperationCmdGetResultRejectsMalformedEnvelope(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, json.NewEncoder(w).Encode(protocolv2.RequestResultResponse{
			State: "s1",
			Done:  true,
			ResponseEnvelope: &protocolv2.ResponseEnvelope{
				TransportAlg: "ecdh-p256+a256gcm",
				BrowserEphemeralPublicKey: protocolv2.ECP256PublicJWK{
					Kty: "EC", Crv: "P-256",
					X: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
					Y: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
					D: "forbidden",
				},
				Nonce:      base64.RawURLEncoding.EncodeToString([]byte("123456789012")),
				Ciphertext: base64.RawURLEncoding.EncodeToString([]byte("x")),
			},
		}))
	}))
	defer srv.Close()
	impl := &v2OperationCmd{flags: &testV2Flags{server: srv.URL, body: []byte(`{}`), alg: "aes-gcm-256"}}

	clientPriv, err := ecdh.P256().GenerateKey(rand.Reader)
	require.NoError(t, err)
	_, err = impl.getResult(context.Background(), srv.Client(), "s1", clientPriv, buildTransportAAD("s1", "", "aes-gcm-256"))
	require.Error(t, err)
}
