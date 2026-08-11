//go:build unit

package clienttest

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/italypaleale/revaulter/internal/clientcore"
	"github.com/italypaleale/revaulter/internal/protocolv2"
)

const (
	// RequestKey is the request key the server accepts
	RequestKey = "request-key-abc"
	// UserID is the ID of the simulated user
	UserID = "user-1"
)

// Server simulates a Revaulter server and the browser attached to it
// It performs the real cryptographic operations, so tests exercise the full request path: E2EE request payload, operation, and E2EE response envelope
// Approval in the browser is implicit: every request is approved as soon as its result is requested
type Server struct {
	// Address of the server
	URL string

	t   *testing.T
	srv *httptest.Server

	// Static request-encryption keys of the simulated user
	ecdhPriv *ecdh.PrivateKey
	mlkemDK  *mlkem.DecapsulationKey768

	// Key material the simulated browser holds
	contentKey []byte
	es256Key   *ecdsa.PrivateKey
	ed25519Key ed25519.PrivateKey

	mu        sync.Mutex
	counter   int
	pending   map[string]*pendingRequest
	lastNote  string
	lastAgent string
}

// pendingRequest is a request the simulated browser has received but not yet performed
type pendingRequest struct {
	Operation string
	Algorithm string
	KeyLabel  string
	Inner     protocolv2.RequestPayloadInner
}

// NewServer starts a simulated Revaulter server, which is stopped when the test ends
func NewServer(t *testing.T) *Server {
	t.Helper()

	ecdhPriv, err := ecdh.P256().GenerateKey(rand.Reader)
	require.NoError(t, err)
	mlkemDK, err := mlkem.GenerateKey768()
	require.NoError(t, err)
	es256Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	_, ed25519Key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	contentKey := make([]byte, 32)
	_, err = rand.Read(contentKey)
	require.NoError(t, err)

	f := &Server{
		t:          t,
		ecdhPriv:   ecdhPriv,
		mlkemDK:    mlkemDK,
		contentKey: contentKey,
		es256Key:   es256Key,
		ed25519Key: ed25519Key,
		pending:    make(map[string]*pendingRequest),
	}

	f.srv = httptest.NewServer(http.HandlerFunc(f.handle))
	f.URL = f.srv.URL
	t.Cleanup(f.srv.Close)

	return f
}

// HTTPClient returns an HTTP client that can reach the server
func (f *Server) HTTPClient() *http.Client {
	return f.srv.Client()
}

// ES256PublicKey returns the public part of the ES256 signing key the simulated browser signs with
func (f *Server) ES256PublicKey() *ecdsa.PublicKey {
	return &f.es256Key.PublicKey
}

// Ed25519PublicKey returns the public part of the Ed25519 signing key the simulated browser signs with
func (f *Server) Ed25519PublicKey() ed25519.PublicKey {
	pub, _ := f.ed25519Key.Public().(ed25519.PublicKey)
	return pub
}

// LastNote returns the note attached to the most recent request
func (f *Server) LastNote() string {
	f.mu.Lock()
	defer f.mu.Unlock()

	return f.lastNote
}

// LastUserAgent returns the User-Agent header of the most recent request
func (f *Server) LastUserAgent() string {
	f.mu.Lock()
	defer f.mu.Unlock()

	return f.lastAgent
}

func (f *Server) handle(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer "+RequestKey {
		http.Error(w, "invalid request key", http.StatusUnauthorized)
		return
	}

	f.mu.Lock()
	f.lastAgent = r.Header.Get("User-Agent")
	f.mu.Unlock()

	path := strings.TrimPrefix(r.URL.Path, "/v2/request/")
	switch {
	case r.Method == http.MethodGet && path == "pubkey":
		f.handlePubkey(w)
	case r.Method == http.MethodGet && path == "signing-pubkey":
		f.handleSigningPubkey(w, r)
	case r.Method == http.MethodGet && strings.HasPrefix(path, "result/"):
		f.handleResult(w, strings.TrimPrefix(path, "result/"))
	case r.Method == http.MethodPost:
		f.handleCreate(w, r, path)
	default:
		http.NotFound(w, r)
	}
}

func (f *Server) handlePubkey(w http.ResponseWriter) {
	jwk, err := protocolv2.ECP256PublicJWKFromECDH(f.ecdhPriv.PublicKey())
	require.NoError(f.t, err)
	ecdhJSON, err := json.Marshal(jwk)
	require.NoError(f.t, err)

	writeJSON(w, map[string]any{
		"userId":   UserID,
		"ecdhP256": json.RawMessage(ecdhJSON),
		"mlkem768": base64.RawURLEncoding.EncodeToString(f.mlkemDK.EncapsulationKey().Bytes()),
	})
}

func (f *Server) handleSigningPubkey(w http.ResponseWriter, r *http.Request) {
	algorithm := r.URL.Query().Get("algorithm")
	keyLabel := r.URL.Query().Get("label")

	var jwk any
	switch algorithm {
	case protocolv2.SigningAlgES256:
		ecdhPub, err := f.es256Key.PublicKey.ECDH()
		require.NoError(f.t, err)
		signingJWK, err := protocolv2.ECP256SigningJWKFromECDH(ecdhPub)
		require.NoError(f.t, err)
		jwk = signingJWK
	case protocolv2.SigningAlgEd25519, protocolv2.SigningAlgEd25519ph:
		signingJWK, err := protocolv2.Ed25519SigningJWKFromPublicKey(f.Ed25519PublicKey())
		require.NoError(f.t, err)
		jwk = signingJWK
	default:
		http.Error(w, "unsupported algorithm", http.StatusBadRequest)
		return
	}

	jwkJSON, err := json.Marshal(jwk)
	require.NoError(f.t, err)

	writeJSON(w, map[string]any{
		"id":        "key-1",
		"algorithm": algorithm,
		"keyLabel":  keyLabel,
		"jwk":       json.RawMessage(jwkJSON),
	})
}

// handleCreate decrypts the E2EE request payload and stores it until the result is requested
func (f *Server) handleCreate(w http.ResponseWriter, r *http.Request, operation string) {
	defer r.Body.Close()

	var body struct {
		KeyLabel              string                     `json:"keyLabel"`
		Algorithm             string                     `json:"algorithm"`
		Timeout               string                     `json:"timeout"`
		Note                  string                     `json:"note"`
		RequestEncAlg         string                     `json:"requestEncAlg"`
		CliEphemeralPublicKey protocolv2.ECP256PublicJWK `json:"cliEphemeralPublicKey"`
		MlkemCiphertext       string                     `json:"mlkemCiphertext"`
		EncryptedPayloadNonce string                     `json:"encryptedPayloadNonce"`
		EncryptedPayload      string                     `json:"encryptedPayload"`
	}
	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if body.RequestEncAlg != protocolv2.TransportAlg {
		http.Error(w, "unexpected requestEncAlg", http.StatusBadRequest)
		return
	}

	// Derive the request encryption key: hybrid ECDH + ML-KEM
	cliEphPub, err := body.CliEphemeralPublicKey.ToECDHPublicKey()
	require.NoError(f.t, err)
	ecdhShared, err := f.ecdhPriv.ECDH(cliEphPub)
	require.NoError(f.t, err)
	mlkemCT, err := base64.RawURLEncoding.DecodeString(body.MlkemCiphertext)
	require.NoError(f.t, err)
	mlkemShared, err := f.mlkemDK.Decapsulate(mlkemCT)
	require.NoError(f.t, err)

	key, err := hkdf.Key(sha256.New, append(append([]byte{}, ecdhShared...), mlkemShared...), nil, "revaulter/v2/request-enc", 32)
	require.NoError(f.t, err)

	nonce, err := base64.RawURLEncoding.DecodeString(body.EncryptedPayloadNonce)
	require.NoError(f.t, err)
	ct, err := base64.RawURLEncoding.DecodeString(body.EncryptedPayload)
	require.NoError(f.t, err)

	aad := clientcore.BuildRequestEncAAD(body.Algorithm, body.KeyLabel, operation)
	plaintext, err := aesGCMOpen(key, nonce, ct, aad)
	if err != nil {
		http.Error(w, "failed to decrypt request payload: "+err.Error(), http.StatusBadRequest)
		return
	}

	var inner protocolv2.RequestPayloadInner
	err = json.Unmarshal(plaintext, &inner)
	require.NoError(f.t, err)

	f.mu.Lock()
	f.counter++
	state := "state-" + strconv.Itoa(f.counter)
	f.pending[state] = &pendingRequest{
		Operation: operation,
		Algorithm: body.Algorithm,
		KeyLabel:  body.KeyLabel,
		Inner:     inner,
	}
	f.lastNote = body.Note
	f.mu.Unlock()

	writeJSON(w, protocolv2.RequestResultResponse{State: state, Pending: true})
}

// handleResult performs the requested operation and returns the E2EE response envelope
func (f *Server) handleResult(w http.ResponseWriter, state string) {
	f.mu.Lock()
	req, ok := f.pending[state]
	f.mu.Unlock()
	if !ok {
		http.Error(w, "unknown state", http.StatusNotFound)
		return
	}

	payload, err := f.performOperation(state, req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Encrypt the response to the client's ephemeral transport keys
	clientEcdhPub, err := req.Inner.ClientTransportEcdhKey.ToECDHPublicKey()
	require.NoError(f.t, err)
	browserEcdhPriv, err := ecdh.P256().GenerateKey(rand.Reader)
	require.NoError(f.t, err)
	ecdhShared, err := browserEcdhPriv.ECDH(clientEcdhPub)
	require.NoError(f.t, err)

	clientMlkemPubBytes, err := base64.RawURLEncoding.DecodeString(req.Inner.ClientTransportMlkemKey)
	require.NoError(f.t, err)
	clientMlkemPub, err := mlkem.NewEncapsulationKey768(clientMlkemPubBytes)
	require.NoError(f.t, err)
	mlkemShared, mlkemCT := clientMlkemPub.Encapsulate()

	key, err := clientcore.DeriveTransportKey(append(append([]byte{}, ecdhShared...), mlkemShared...), state)
	require.NoError(f.t, err)

	aad := clientcore.BuildTransportAAD(state, req.Operation, req.Algorithm)
	nonce, ct, err := aesGCMSeal(key, payload, aad)
	require.NoError(f.t, err)

	browserJWK, err := protocolv2.ECP256PublicJWKFromECDH(browserEcdhPriv.PublicKey())
	require.NoError(f.t, err)

	writeJSON(w, protocolv2.RequestResultResponse{
		State: state,
		Done:  true,
		ResponseEnvelope: &protocolv2.ResponseEnvelope{
			TransportAlg:              protocolv2.TransportAlg,
			BrowserEphemeralPublicKey: browserJWK,
			MlkemCiphertext:           base64.RawURLEncoding.EncodeToString(mlkemCT),
			Nonce:                     base64.RawURLEncoding.EncodeToString(nonce),
			Ciphertext:                base64.RawURLEncoding.EncodeToString(ct),
		},
	})
}

// performOperation runs the operation the browser would perform locally, and returns the JSON payload it produces
func (f *Server) performOperation(state string, req *pendingRequest) ([]byte, error) {
	value, err := base64.RawURLEncoding.DecodeString(req.Inner.Value)
	if err != nil {
		return nil, err
	}
	aad, err := base64.RawURLEncoding.DecodeString(req.Inner.AdditionalData)
	if err != nil {
		return nil, err
	}

	switch req.Operation {
	case protocolv2.OperationEncrypt:
		nonce, combined, err := aesGCMSeal(f.contentKey, value, aad)
		if err != nil {
			return nil, err
		}

		// The browser splits the tag out of the combined AEAD output
		ciphertext := combined[:len(combined)-16]
		tag := combined[len(combined)-16:]
		out := map[string]any{
			"state":     state,
			"operation": req.Operation,
			"algorithm": req.Algorithm,
			"value":     base64.RawURLEncoding.EncodeToString(ciphertext),
			"nonce":     base64.RawURLEncoding.EncodeToString(nonce),
			"tag":       base64.RawURLEncoding.EncodeToString(tag),
		}
		if req.Inner.AdditionalData != "" {
			out["additionalData"] = req.Inner.AdditionalData
		}
		return json.Marshal(out)

	case protocolv2.OperationDecrypt:
		nonce, err := base64.RawURLEncoding.DecodeString(req.Inner.Nonce)
		if err != nil {
			return nil, err
		}
		tag, err := base64.RawURLEncoding.DecodeString(req.Inner.Tag)
		if err != nil {
			return nil, err
		}

		plaintext, err := aesGCMOpen(f.contentKey, nonce, append(append([]byte{}, value...), tag...), aad)
		if err != nil {
			return nil, err
		}

		return json.Marshal(map[string]any{
			"state":     state,
			"operation": req.Operation,
			"algorithm": req.Algorithm,
			"value":     base64.RawURLEncoding.EncodeToString(plaintext),
		})

	case protocolv2.OperationSign:
		signature, keyID, err := f.sign(req.Algorithm, value)
		if err != nil {
			return nil, err
		}

		return json.Marshal(map[string]any{
			"state":        state,
			"operation":    req.Operation,
			"algorithm":    req.Algorithm,
			"keyLabel":     req.KeyLabel,
			"signature":    base64.RawURLEncoding.EncodeToString(signature),
			"signingKeyId": keyID,
		})

	default:
		return nil, errUnsupportedOperation
	}
}

// sign produces a signature the same way the browser does, and returns it alongside the thumbprint of the signing key
func (f *Server) sign(algorithm string, value []byte) ([]byte, string, error) {
	switch algorithm {
	case protocolv2.SigningAlgES256:
		r, s, err := ecdsa.Sign(rand.Reader, f.es256Key, value)
		if err != nil {
			return nil, "", err
		}
		sig := make([]byte, 64)
		r.FillBytes(sig[:32])
		s.FillBytes(sig[32:])

		ecdhPub, err := f.es256Key.PublicKey.ECDH()
		if err != nil {
			return nil, "", err
		}
		jwk, err := protocolv2.ECP256SigningJWKFromECDH(ecdhPub)
		if err != nil {
			return nil, "", err
		}
		keyID, err := jwk.Thumbprint()
		if err != nil {
			return nil, "", err
		}

		return sig, keyID, nil

	case protocolv2.SigningAlgEd25519, protocolv2.SigningAlgEd25519ph:
		opts := crypto.SignerOpts(crypto.Hash(0))
		if algorithm == protocolv2.SigningAlgEd25519ph {
			opts = &ed25519.Options{Hash: crypto.SHA512}
		}
		sig, err := f.ed25519Key.Sign(rand.Reader, value, opts)
		if err != nil {
			return nil, "", err
		}

		jwk, err := protocolv2.Ed25519SigningJWKFromPublicKey(f.Ed25519PublicKey())
		if err != nil {
			return nil, "", err
		}
		keyID, err := jwk.Thumbprint()
		if err != nil {
			return nil, "", err
		}

		return sig, keyID, nil

	default:
		return nil, "", errUnsupportedOperation
	}
}

var errUnsupportedOperation = &unsupportedOperationError{}

type unsupportedOperationError struct{}

func (e *unsupportedOperationError) Error() string {
	return "unsupported operation"
}

func aesGCMSeal(key, plaintext, aad []byte) (nonce []byte, ciphertext []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, gcm.NonceSize())
	_, err = rand.Read(nonce)
	if err != nil {
		return nil, nil, err
	}

	return nonce, gcm.Seal(nil, nonce, plaintext, aad), nil
}

func aesGCMOpen(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return gcm.Open(nil, nonce, ciphertext, aad)
}

func writeJSON(w http.ResponseWriter, body any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(body)
}
