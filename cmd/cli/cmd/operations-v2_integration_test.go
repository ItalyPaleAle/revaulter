package cmd

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
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
	server   string
	alg      string
	keyLabel string
	output   string
	raw      bool
}

func (f *testV2Flags) BindToCommand(_ *cobra.Command)      {}
func (f *testV2Flags) Validate() error                      { return nil }
func (f *testV2Flags) GetServer() string                    { return f.server }
func (f *testV2Flags) GetRequestKey() string                { return "request-key-123" }
func (f *testV2Flags) GetKeyLabel() string                  { return f.keyLabel }
func (f *testV2Flags) GetAlgorithm() string                 { return f.alg }
func (f *testV2Flags) GetTimeout() string                   { return "" }
func (f *testV2Flags) GetNote() string                      { return "" }
func (f *testV2Flags) GetConnectionOptions() (bool, bool)   { return false, false }
func (f *testV2Flags) GetOutput() string                    { return f.output }
func (f *testV2Flags) GetRaw() bool                         { return f.raw }
func (f *testV2Flags) InnerPayload(clientTransportEcdhKey protocolv2.ECP256PublicJWK, clientTransportMlkemKey string) protocolv2.RequestPayloadInner {
	return protocolv2.RequestPayloadInner{
		Value:                   base64.RawURLEncoding.EncodeToString([]byte("hello")),
		ClientTransportEcdhKey:  clientTransportEcdhKey,
		ClientTransportMlkemKey: clientTransportMlkemKey,
	}
}

func TestV2OperationCmdCreateAndDecryptResult(t *testing.T) {
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
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/v2/request/request-key-123/pubkey"):
			w.Header().Set("Content-Type", "application/json")
			ecdhJSON, _ := json.Marshal(userStaticEcdhPubJWK)
			resp := map[string]any{
				"ecdhP256": json.RawMessage(ecdhJSON),
				"mlkem768": userStaticMlkemPubB64,
			}
			require.NoError(t, json.NewEncoder(w).Encode(resp))

		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/v2/request/request-key-123/encrypt"):
			defer r.Body.Close()
			createSeen.Store(true)

			var req v2OperationRequest
			require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
			require.Equal(t, "disk-key", req.KeyLabel)
			require.Equal(t, "aes-gcm-256", req.Algorithm)
			require.Equal(t, "ecdh-p256+mlkem768+a256gcm", req.RequestEncAlg)
			require.NoError(t, req.CliEphemeralPublicKey.ValidatePublic())
			require.NotEmpty(t, req.MlkemCiphertext)

			// Decrypt the E2EE payload using hybrid ECDH + ML-KEM
			cliEphPub, err := req.CliEphemeralPublicKey.ToECDHPublicKey()
			require.NoError(t, err)
			ecdhShared, err := userStaticEcdhPriv.ECDH(cliEphPub)
			require.NoError(t, err)

			mlkemCT, err := base64.RawURLEncoding.DecodeString(req.MlkemCiphertext)
			require.NoError(t, err)
			mlkemShared, err := userStaticMlkemDK.Decapsulate(mlkemCT)
			require.NoError(t, err)

			combined := append(ecdhShared, mlkemShared...)
			aesKey, err := hkdf.Key(sha256.New, combined, nil, "revaulter/v2/request-enc", 32)
			require.NoError(t, err)
			block, err := aes.NewCipher(aesKey)
			require.NoError(t, err)
			gcm, err := cipher.NewGCM(block)
			require.NoError(t, err)
			nonce, err := base64.RawURLEncoding.DecodeString(req.EncryptedPayloadNonce)
			require.NoError(t, err)
			ct, err := base64.RawURLEncoding.DecodeString(req.EncryptedPayload)
			require.NoError(t, err)
			aad := buildRequestEncAAD("aes-gcm-256", "disk-key", "encrypt")
			plaintext, err := gcm.Open(nil, nonce, ct, aad)
			require.NoError(t, err)

			var inner protocolv2.RequestPayloadInner
			require.NoError(t, json.Unmarshal(plaintext, &inner))
			require.NoError(t, inner.ClientTransportEcdhKey.ValidatePublic())
			require.NotEmpty(t, inner.ClientTransportMlkemKey)
			capturedClientTransportEcdhKey = inner.ClientTransportEcdhKey
			capturedClientTransportMlkemKey = inner.ClientTransportMlkemKey

			w.Header().Set("Content-Type", "application/json")
			require.NoError(t, json.NewEncoder(w).Encode(protocolv2.RequestResultResponse{
				State:   state,
				Pending: true,
			}))

		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/v2/request/result/"+state):
			require.True(t, createSeen.Load())

			// ECDH key agreement for transport
			clientEcdhPub, err := capturedClientTransportEcdhKey.ToECDHPublicKey()
			require.NoError(t, err)
			browserEcdhPriv, err := ecdh.P256().GenerateKey(rand.Reader)
			require.NoError(t, err)
			ecdhShared, err := browserEcdhPriv.ECDH(clientEcdhPub)
			require.NoError(t, err)

			// ML-KEM encapsulation for transport
			clientMlkemPubBytes, err := base64.RawURLEncoding.DecodeString(capturedClientTransportMlkemKey)
			require.NoError(t, err)
			clientMlkemPub, err := mlkem.NewEncapsulationKey768(clientMlkemPubBytes)
			require.NoError(t, err)
			mlkemShared, mlkemCT := clientMlkemPub.Encapsulate()

			// Combine secrets
			combined := append(ecdhShared, mlkemShared...)
			key, err := deriveV2TransportKey(combined, state)
			require.NoError(t, err)

			block, err := aes.NewCipher(key)
			require.NoError(t, err)
			aead, err := cipher.NewGCM(block)
			require.NoError(t, err)
			nonce := make([]byte, aead.NonceSize())
			_, err = rand.Read(nonce)
			require.NoError(t, err)
			aadBytes := buildTransportAAD(state, "encrypt", "aes-gcm-256")
			ct := aead.Seal(nil, nonce, plainResp, aadBytes)
			browserJWK, err := protocolv2.ECP256PublicJWKFromECDH(browserEcdhPriv.PublicKey())
			require.NoError(t, err)

			w.Header().Set("Content-Type", "application/json")
			require.NoError(t, json.NewEncoder(w).Encode(protocolv2.RequestResultResponse{
				State: state,
				Done:  true,
				ResponseEnvelope: &protocolv2.ResponseEnvelope{
					TransportAlg:              "ecdh-p256+mlkem768+a256gcm",
					BrowserEphemeralPublicKey: browserJWK,
					MlkemCiphertext:           base64.RawURLEncoding.EncodeToString(mlkemCT),
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

	impl := &v2OperationCmd{
		Operation: "encrypt",
		flags: &testV2Flags{
			server:   srv.URL,
			keyLabel: "disk-key",
			alg:      "aes-gcm-256",
		},
	}
	kp, err := newV2TransportKeyPair()
	require.NoError(t, err)
	gotState, err := impl.createRequest(context.Background(), srv.Client(), kp)
	require.NoError(t, err)
	require.Equal(t, state, gotState)
	got, err := impl.getResult(context.Background(), srv.Client(), gotState, kp, buildTransportAAD(gotState, "encrypt", "aes-gcm-256"))
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
	impl := &v2OperationCmd{flags: &testV2Flags{server: srv.URL, alg: "aes-gcm-256", keyLabel: "k"}}

	kp, err := newV2TransportKeyPair()
	require.NoError(t, err)
	_, err = impl.getResult(context.Background(), srv.Client(), "s1", kp, buildTransportAAD("s1", "", "aes-gcm-256"))
	require.ErrorContains(t, err, "canceled, denied, or failed")
}

func TestV2OperationCmdGetResultStateMismatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, json.NewEncoder(w).Encode(protocolv2.RequestResultResponse{
			State: "other",
			Done:  true,
			ResponseEnvelope: &protocolv2.ResponseEnvelope{
				TransportAlg: "ecdh-p256+mlkem768+a256gcm",
				BrowserEphemeralPublicKey: protocolv2.ECP256PublicJWK{
					Kty: "EC", Crv: "P-256",
					X: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
					Y: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
				},
				MlkemCiphertext: base64.RawURLEncoding.EncodeToString(make([]byte, 1088)),
				Nonce:           base64.RawURLEncoding.EncodeToString([]byte("123456789012")),
				Ciphertext:      base64.RawURLEncoding.EncodeToString([]byte("x")),
			},
		}))
	}))
	defer srv.Close()
	impl := &v2OperationCmd{flags: &testV2Flags{server: srv.URL, alg: "aes-gcm-256", keyLabel: "k"}}

	kp, err := newV2TransportKeyPair()
	require.NoError(t, err)
	_, err = impl.getResult(context.Background(), srv.Client(), "expected", kp, buildTransportAAD("expected", "", "aes-gcm-256"))
	require.ErrorContains(t, err, "response state mismatch")
}

func TestV2OperationCmdGetResultRejectsMalformedEnvelope(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, json.NewEncoder(w).Encode(protocolv2.RequestResultResponse{
			State: "s1",
			Done:  true,
			ResponseEnvelope: &protocolv2.ResponseEnvelope{
				TransportAlg: "ecdh-p256+mlkem768+a256gcm",
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
		}))
	}))
	defer srv.Close()
	impl := &v2OperationCmd{flags: &testV2Flags{server: srv.URL, alg: "aes-gcm-256", keyLabel: "k"}}

	kp, err := newV2TransportKeyPair()
	require.NoError(t, err)
	_, err = impl.getResult(context.Background(), srv.Client(), "s1", kp, buildTransportAAD("s1", "", "aes-gcm-256"))
	require.Error(t, err)
}
