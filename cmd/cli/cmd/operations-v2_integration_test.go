package cmd

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

func (f *testV2Flags) BindToCommand(_ *cobra.Command)     {}
func (f *testV2Flags) Validate() error                    { return nil }
func (f *testV2Flags) GetServer() string                  { return f.server }
func (f *testV2Flags) GetRequestKey() string              { return "request-key-123" }
func (f *testV2Flags) GetKeyLabel() string                { return f.keyLabel }
func (f *testV2Flags) GetAlgorithm() string               { return f.alg }
func (f *testV2Flags) GetTimeout() string                 { return "" }
func (f *testV2Flags) GetNote() string                    { return "" }
func (f *testV2Flags) GetConnectionOptions() (bool, bool) { return false, false }
func (f *testV2Flags) GetOutput() string                  { return f.output }
func (f *testV2Flags) GetRaw() bool                       { return f.raw }
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
			err := json.NewEncoder(w).Encode(resp)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/v2/request/request-key-123/encrypt"):
			defer r.Body.Close()
			createSeen.Store(true)

			var req v2OperationRequest
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
			aad := buildRequestEncAAD("A256GCM", "disk-key", "encrypt")
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

		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/v2/request/result/"+state):
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
			key, err := deriveV2TransportKey(combined, state)
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
			aadBytes := buildTransportAAD(state, "encrypt", "A256GCM")
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

	impl := &v2OperationCmd{
		Operation: "encrypt",
		flags: &testV2Flags{
			server:   srv.URL,
			keyLabel: "disk-key",
			alg:      "A256GCM",
		},
	}
	kp, err := newV2TransportKeyPair()
	require.NoError(t, err)
	gotState, err := impl.createRequest(context.Background(), srv.Client(), kp)
	require.NoError(t, err)
	require.Equal(t, state, gotState)
	got, err := impl.getResult(context.Background(), srv.Client(), gotState, kp, buildTransportAAD(gotState, "encrypt", "A256GCM"))
	require.NoError(t, err)
	require.JSONEq(t, string(plainResp), string(got))
	require.True(t, createSeen.Load())
}

func TestV2OperationCmdGetResultFailed(t *testing.T) {
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
	impl := &v2OperationCmd{flags: &testV2Flags{server: srv.URL, alg: "A256GCM", keyLabel: "k"}}

	kp, err := newV2TransportKeyPair()
	require.NoError(t, err)
	_, err = impl.getResult(context.Background(), srv.Client(), "s1", kp, buildTransportAAD("s1", "", "A256GCM"))
	require.ErrorContains(t, err, "canceled, denied, or failed")
}

func TestV2OperationCmdGetResultStateMismatch(t *testing.T) {
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
	impl := &v2OperationCmd{flags: &testV2Flags{server: srv.URL, alg: "A256GCM", keyLabel: "k"}}

	kp, err := newV2TransportKeyPair()
	require.NoError(t, err)
	_, err = impl.getResult(context.Background(), srv.Client(), "expected", kp, buildTransportAAD("expected", "", "A256GCM"))
	require.ErrorContains(t, err, "response state mismatch")
}

// testV2SignFlags mirrors testV2Flags but emits a sign-shaped inner payload
// The sign op puts the digest in Value and leaves nonce/tag/aad empty
type testV2SignFlags struct {
	server    string
	keyLabel  string
	digestB64 string
}

func (f *testV2SignFlags) BindToCommand(_ *cobra.Command)     {}
func (f *testV2SignFlags) Validate() error                    { return nil }
func (f *testV2SignFlags) GetServer() string                  { return f.server }
func (f *testV2SignFlags) GetRequestKey() string              { return "request-key-sign" }
func (f *testV2SignFlags) GetKeyLabel() string                { return f.keyLabel }
func (f *testV2SignFlags) GetAlgorithm() string               { return protocolv2.SigningAlgES256 }
func (f *testV2SignFlags) GetTimeout() string                 { return "" }
func (f *testV2SignFlags) GetNote() string                    { return "" }
func (f *testV2SignFlags) GetConnectionOptions() (bool, bool) { return false, false }
func (f *testV2SignFlags) GetOutput() string                  { return "" }
func (f *testV2SignFlags) GetRaw() bool                       { return false }
func (f *testV2SignFlags) InnerPayload(clientTransportEcdhKey protocolv2.ECP256PublicJWK, clientTransportMlkemKey string) protocolv2.RequestPayloadInner {
	return protocolv2.RequestPayloadInner{
		Value:                   f.digestB64,
		ClientTransportEcdhKey:  clientTransportEcdhKey,
		ClientTransportMlkemKey: clientTransportMlkemKey,
	}
}

// TestV2OperationCmdSignAndVerify exercises the full sign flow end to end:
// the CLI sends an encrypted digest, the simulated browser signs it with a
// freshly generated ECDSA P-256 key, the CLI decrypts the response envelope,
// and the test verifies the signature against that same public key
func TestV2OperationCmdSignAndVerify(t *testing.T) {
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
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/v2/request/request-key-sign/pubkey"):
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

		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/v2/request/request-key-sign/sign"):
			defer r.Body.Close()
			createSeen.Store(true)

			var req v2OperationRequest
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
			aad := buildRequestEncAAD(protocolv2.SigningAlgES256, keyLabel, protocolv2.OperationSign)
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

		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/v2/request/result/"+state):
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
			key, err := deriveV2TransportKey(combined, state)
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
			aadBytes := buildTransportAAD(state, protocolv2.OperationSign, protocolv2.SigningAlgES256)
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

	impl := &v2OperationCmd{
		Operation: protocolv2.OperationSign,
		flags: &testV2SignFlags{
			server:    srv.URL,
			keyLabel:  keyLabel,
			digestB64: digestB64,
		},
	}
	kp, err := newV2TransportKeyPair()
	require.NoError(t, err)
	gotState, err := impl.createRequest(context.Background(), srv.Client(), kp)
	require.NoError(t, err)
	require.Equal(t, state, gotState)

	aad := buildTransportAAD(gotState, protocolv2.OperationSign, protocolv2.SigningAlgES256)
	got, err := impl.getResult(context.Background(), srv.Client(), gotState, kp, aad)
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

func TestV2OperationCmdGetResultRejectsMalformedEnvelope(t *testing.T) {
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
	impl := &v2OperationCmd{flags: &testV2Flags{server: srv.URL, alg: "A256GCM", keyLabel: "k"}}

	kp, err := newV2TransportKeyPair()
	require.NoError(t, err)
	_, err = impl.getResult(context.Background(), srv.Client(), "s1", kp, buildTransportAAD("s1", "", "A256GCM"))
	require.Error(t, err)
}
