package server

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/italypaleale/revaulter/internal/db"
	"github.com/italypaleale/revaulter/internal/protocolv2"
)

// pairingTest plays both sides of a pairing: the existing client, which has a session cookie and knows the payload secret, and the new device
type pairingTest struct {
	srv    *Server
	client *http.Client
	cookie *http.Cookie
	userID string
	anchor *testAnchorKeyPair
	device *testDeviceKeys

	// Set by create
	sessionID string
	macKey    []byte
}

func newPairingTest(t *testing.T, dbName string) *pairingTest {
	t.Helper()

	setTestConfig(t, dbName)
	srv := newTestServer(t, nil, nil, nil)
	startTestServer(t, srv)

	cookie, _ := seedV2SessionCookie(t, srv, "user-alice", "Alice")
	anchor := seedV2AnchorForUser(t, srv, "user-alice")

	return &pairingTest{
		srv:    srv,
		client: clientForListener(srv.appListener),
		cookie: cookie,
		userID: "user-alice",
		anchor: anchor,
		device: newTestDeviceKeys(t),
	}
}

func (pt *pairingTest) serverURL() string {
	return fmt.Sprintf("https://localhost:%d", testServerPort)
}

func (pt *pairingTest) anchorFingerprint(t *testing.T) string {
	t.Helper()

	fp, err := protocolv2.AnchorFingerprint(&pt.anchor.Es384Priv.PublicKey, pt.anchor.Mldsa87PubBytes)
	require.NoError(t, err)

	return fp
}

// create opens a pairing session as the existing client and generates the payload secret
func (pt *pairingTest) create(t *testing.T) {
	t.Helper()

	status, out := doV2JSON(t, pt.client, http.MethodPost, "/v2/auth/pairing/create", protocolv2.PairingCreateRequest{Server: pt.serverURL()}, withCookie(pt.cookie))
	require.Equal(t, http.StatusOK, status, out)

	pt.sessionID, _ = out["sessionId"].(string)
	require.True(t, isPairingSessionID(pt.sessionID))
	expiresAt, _ := out["expiresAt"].(float64)
	require.InDelta(t, time.Now().Add(protocolv2.PairingTTL).Unix(), int64(expiresAt), 5)

	secret := make([]byte, protocolv2.PairingSecretSize)
	_, err := rand.Read(secret)
	require.NoError(t, err)
	pt.macKey, err = protocolv2.PairingMACKey(secret, pt.sessionID)
	require.NoError(t, err)
}

// hello builds the hello the device sends for the current session, signed and MAC'd over the given transcript fields
func (pt *pairingTest) hello(t *testing.T, device *testDeviceKeys) protocolv2.PairingHello {
	t.Helper()
	return pt.helloFor(t, device, pt.serverURL(), pt.sessionID)
}

func (pt *pairingTest) helloFor(t *testing.T, device *testDeviceKeys, server string, sessionID string) protocolv2.PairingHello {
	t.Helper()

	hello := protocolv2.PairingHello{
		DeviceName:   "Alice's iPhone",
		CredentialID: device.credentialID,
		PublicKeys:   device.public,
	}
	transcript := protocolv2.NewPairingTranscript(server, pt.userID, sessionID, pt.anchorFingerprint(t), &hello)
	hello.SignatureP256, hello.SignatureMldsa65 = device.sign(t, protocolv2.CanonicalPairingHelloMessage(&transcript))
	hello.MAC = base64.RawURLEncoding.EncodeToString(protocolv2.PairingHelloMAC(pt.macKey, &transcript))

	return hello
}

func (pt *pairingTest) sendHello(t *testing.T, hello protocolv2.PairingHello) (int, map[string]any) {
	t.Helper()
	return doV2JSON(t, pt.client, http.MethodPost, "/v2/auth/pairing/hello", protocolv2.PairingHelloRequest{SessionID: pt.sessionID, Hello: hello}, nil)
}

// sendNonce sends a nonce for the accepted hello as the existing client and returns the status and the comparison code
func (pt *pairingTest) sendNonce(t *testing.T, hello protocolv2.PairingHello) (int, string) {
	t.Helper()

	nonce := make([]byte, protocolv2.PairingNonceSize)
	_, err := rand.Read(nonce)
	require.NoError(t, err)
	payload := protocolv2.PairingNoncePayload{
		HelloMAC: hello.MAC,
		Nonce:    base64.RawURLEncoding.EncodeToString(nonce),
		V:        protocolv2.PairingVersion,
	}

	status, _ := doV2JSON(t, pt.client, http.MethodPost, "/v2/auth/pairing/nonce", protocolv2.PairingNonceRequest{
		SessionID: pt.sessionID,
		Nonce:     payload.Nonce,
		NonceMAC:  base64.RawURLEncoding.EncodeToString(protocolv2.PairingNonceMAC(pt.macKey, &payload)),
	}, withCookie(pt.cookie))

	return status, protocolv2.PairingCode(pt.macKey, &payload)
}

// completeRequest builds a valid completion for device; mutate can change the attestation payload before it is signed
func (pt *pairingTest) completeRequest(t *testing.T, device *testDeviceKeys, mutate func(p *protocolv2.AttestationPayloadV2)) protocolv2.PairingCompleteRequest {
	t.Helper()

	user, err := pt.srv.db.AuthStore().GetUserByID(t.Context(), pt.userID)
	require.NoError(t, err)
	require.NotNil(t, user)

	payload := protocolv2.AttestationPayloadV2{
		UserID:                  pt.userID,
		CredentialID:            device.credentialID,
		CredentialType:          protocolv2.CredentialTypeDevice,
		CredentialPublicKeyHash: device.public.Hash(),
		WrappedKeyEpoch:         user.WrappedKeyEpoch,
		CreatedAt:               time.Now().Unix(),
		V:                       protocolv2.AttestationVersion2,
	}
	if mutate != nil {
		mutate(&payload)
	}
	sigEs, sigMl := signHybridMessage(t, pt.anchor, protocolv2.CanonicalAttestationMessageV2(&payload))

	return protocolv2.PairingCompleteRequest{
		SessionID:                   pt.sessionID,
		DisplayName:                 "",
		WrappedPrimaryKey:           testDeviceWrappedPrimaryKey(t, device),
		WrappedAnchorKey:            testValidWrappedAnchorEnvelope(t),
		AttestationPayload:          payload.CanonicalBody(),
		AttestationSignatureEs384:   sigEs,
		AttestationSignatureMldsa87: sigMl,
	}
}

func (pt *pairingTest) complete(t *testing.T, req protocolv2.PairingCompleteRequest) (int, map[string]any) {
	t.Helper()
	return doV2JSON(t, pt.client, http.MethodPost, "/v2/auth/pairing/complete", req, withCookie(pt.cookie))
}

// deviceStatus polls the session as the new device
func (pt *pairingTest) deviceStatus(t *testing.T, sessionID string) (int, map[string]any) {
	t.Helper()
	return doV2JSON(t, pt.client, http.MethodGet, "/v2/auth/pairing/"+sessionID+"/device", nil, nil)
}

// testDeviceWrappedPrimaryKey returns a structurally valid device envelope for device
// The ciphertext is not a real wrap: the server only checks the envelope's structure
func testDeviceWrappedPrimaryKey(t *testing.T, device *testDeviceKeys) string {
	t.Helper()

	eph, err := ecdh.P256().GenerateKey(rand.Reader)
	require.NoError(t, err)
	_, kemCt := device.kem.EncapsulationKey().Encapsulate()

	env := protocolv2.WrappedPrimaryKeyEnvelope{
		V:          protocolv2.WrappedPrimaryKeyVersion,
		Kind:       protocolv2.WrappedKeyKindDevice,
		EphPub:     base64.RawURLEncoding.EncodeToString(eph.PublicKey().Bytes()),
		KemCt:      base64.RawURLEncoding.EncodeToString(kemCt),
		Nonce:      base64.RawURLEncoding.EncodeToString(make([]byte, 12)),
		Ciphertext: base64.RawURLEncoding.EncodeToString(make([]byte, 48)),
	}
	wrapped, err := env.Encode()
	require.NoError(t, err)

	return wrapped
}

func TestServerV2PairingFlow(t *testing.T) {
	pt := newPairingTest(t, "v2-pairing-flow.db")

	// Existing client opens the session and shows the payload
	pt.create(t)
	status, out := pt.deviceStatus(t, pt.sessionID)
	require.Equal(t, http.StatusOK, status, out)
	assert.Equal(t, protocolv2.PairingStatusCreated, out["status"])

	// New device sends its hello, without a session
	hello := pt.hello(t, pt.device)
	status, out = pt.sendHello(t, hello)
	require.Equal(t, http.StatusOK, status, out)

	// Existing client reads the hello and checks its MAC
	status, out = doV2JSON(t, pt.client, http.MethodGet, "/v2/auth/pairing/"+pt.sessionID, nil, withCookie(pt.cookie))
	require.Equal(t, http.StatusOK, status, out)
	assert.Equal(t, protocolv2.PairingStatusHello, out["status"])
	helloJSON, err := json.Marshal(out["hello"])
	require.NoError(t, err)
	var gotHello protocolv2.PairingHello
	err = json.Unmarshal(helloJSON, &gotHello)
	require.NoError(t, err)
	require.Equal(t, hello, gotHello)

	transcript := protocolv2.NewPairingTranscript(pt.serverURL(), pt.userID, pt.sessionID, pt.anchorFingerprint(t), &gotHello)
	mac, err := base64.RawURLEncoding.DecodeString(gotHello.MAC)
	require.NoError(t, err)
	err = protocolv2.VerifyPairingHelloMAC(pt.macKey, &transcript, mac)
	require.NoError(t, err)

	// Existing client sends the nonce
	status, clientCode := pt.sendNonce(t, gotHello)
	require.Equal(t, http.StatusOK, status)

	// New device gets the nonce, checks its MAC and shows the same code
	status, out = pt.deviceStatus(t, pt.sessionID)
	require.Equal(t, http.StatusOK, status, out)
	assert.Equal(t, protocolv2.PairingStatusNonce, out["status"])
	nonce, _ := out["nonce"].(string)
	nonceMACB64, _ := out["nonceMac"].(string)
	noncePayload := protocolv2.PairingNoncePayload{
		HelloMAC: hello.MAC,
		Nonce:    nonce,
		V:        protocolv2.PairingVersion,
	}
	nonceMAC, err := base64.RawURLEncoding.DecodeString(nonceMACB64)
	require.NoError(t, err)
	err = protocolv2.VerifyPairingNonceMAC(pt.macKey, &noncePayload, nonceMAC)
	require.NoError(t, err)
	assert.Equal(t, clientCode, protocolv2.PairingCode(pt.macKey, &noncePayload))

	// Existing client completes the pairing
	completeReq := pt.completeRequest(t, pt.device, nil)
	status, out = pt.complete(t, completeReq)
	require.Equal(t, http.StatusOK, status, out)
	assert.Equal(t, pt.device.credentialID, out["credentialId"])
	recordID, _ := out["id"].(string)
	require.NotEmpty(t, recordID)

	status, out = pt.deviceStatus(t, pt.sessionID)
	require.Equal(t, http.StatusOK, status, out)
	assert.Equal(t, protocolv2.PairingStatusCompleted, out["status"])

	// The device is stored at the current epoch, under the device's name
	cred, err := pt.srv.db.AuthStore().GetCredentialForUser(t.Context(), pt.userID, pt.device.credentialID)
	require.NoError(t, err)
	require.NotNil(t, cred)
	assert.Equal(t, recordID, cred.ID)
	assert.Equal(t, protocolv2.CredentialTypeDevice, cred.CredentialType)
	assert.Equal(t, "Alice's iPhone", cred.DisplayName)
	assert.Equal(t, int64(1), cred.WrappedKeyEpoch)
	assert.Equal(t, completeReq.AttestationPayload, cred.AttestationPayload)
	keys, err := parseStoredDevicePublicKeys(cred.PublicKey)
	require.NoError(t, err)
	require.NotNil(t, keys)

	// The paired device can log in and gets the wrapper made for it
	challengeID, challenge := deviceLoginBegin(t, pt.client, pt.userID, pt.device.credentialID)
	status, out = doV2JSON(t, pt.client, http.MethodPost, "/v2/auth/device/login/finish", signDeviceLogin(t, pt.device, pt.userID, challengeID, challenge), nil)
	require.Equal(t, http.StatusOK, status, out)
	assert.Equal(t, completeReq.WrappedPrimaryKey, out["wrappedPrimaryKey"])

	// Each step that changes state is audited
	for _, eventType := range []db.EventType{db.AuditAuthPairingCreate, db.AuditAuthPairingHello, db.AuditAuthPairingComplete} {
		rows := auditByType(t, pt.srv, pt.userID, eventType)
		require.Len(t, rows, 1, eventType)
		assert.Equal(t, db.AuditOutcomeSuccess, rows[0].Outcome, eventType)
	}
	rows := auditByType(t, pt.srv, pt.userID, db.AuditAuthPairingComplete)
	require.NotNil(t, rows[0].CredentialID)
	assert.Equal(t, pt.device.credentialID, *rows[0].CredentialID)
}

func TestServerV2PairingStepOrder(t *testing.T) {
	pt := newPairingTest(t, "v2-pairing-order.db")
	pt.create(t)
	hello := pt.hello(t, pt.device)

	// Nothing can skip ahead of the hello
	status, _ := pt.sendNonce(t, hello)
	require.Equal(t, http.StatusConflict, status)
	status, _ = pt.complete(t, pt.completeRequest(t, pt.device, nil))
	require.Equal(t, http.StatusConflict, status)

	status, out := pt.sendHello(t, hello)
	require.Equal(t, http.StatusOK, status, out)

	// A second hello is refused, even from another device
	status, _ = pt.sendHello(t, hello)
	require.Equal(t, http.StatusConflict, status)
	status, _ = pt.sendHello(t, pt.hello(t, newTestDeviceKeys(t)))
	require.Equal(t, http.StatusConflict, status)

	// Complete still needs the nonce
	status, _ = pt.complete(t, pt.completeRequest(t, pt.device, nil))
	require.Equal(t, http.StatusConflict, status)

	// The nonce is accepted once
	status, _ = pt.sendNonce(t, hello)
	require.Equal(t, http.StatusOK, status)
	status, _ = pt.sendNonce(t, hello)
	require.Equal(t, http.StatusConflict, status)

	// Complete works once
	status, out = pt.complete(t, pt.completeRequest(t, pt.device, nil))
	require.Equal(t, http.StatusOK, status, out)
	status, _ = pt.complete(t, pt.completeRequest(t, pt.device, nil))
	require.Equal(t, http.StatusConflict, status)
}

func TestServerV2PairingHelloChecks(t *testing.T) {
	pt := newPairingTest(t, "v2-pairing-hello.db")
	pt.create(t)

	t.Run("signatures from other keys", func(t *testing.T) {
		hello := pt.hello(t, pt.device)
		forged := pt.hello(t, newTestDeviceKeys(t))
		hello.SignatureMldsa65 = forged.SignatureMldsa65

		status, _ := pt.sendHello(t, hello)
		require.Equal(t, http.StatusBadRequest, status)
	})

	t.Run("signatures over another server", func(t *testing.T) {
		status, _ := pt.sendHello(t, pt.helloFor(t, pt.device, "https://evil.example.com", pt.sessionID))
		require.Equal(t, http.StatusBadRequest, status)
	})

	t.Run("signatures over another session", func(t *testing.T) {
		otherSession := base64.RawURLEncoding.EncodeToString(make([]byte, protocolv2.PairingSessionIDSize))
		status, _ := pt.sendHello(t, pt.helloFor(t, pt.device, pt.serverURL(), otherSession))
		require.Equal(t, http.StatusBadRequest, status)
	})

	t.Run("malformed keys", func(t *testing.T) {
		hello := pt.hello(t, pt.device)
		hello.PublicKeys.KemMlkem768 = base64.RawURLEncoding.EncodeToString([]byte("short"))

		status, _ := pt.sendHello(t, hello)
		require.Equal(t, http.StatusBadRequest, status)
	})

	t.Run("body over the cap", func(t *testing.T) {
		// Without the cap, the unknown field would be ignored and the hello accepted
		body := map[string]any{
			"sessionId": pt.sessionID,
			"hello":     pt.hello(t, pt.device),
			"padding":   strings.Repeat("a", maxPairingHelloBodySize),
		}
		status, _ := doV2JSON(t, pt.client, http.MethodPost, "/v2/auth/pairing/hello", body, nil)
		require.Equal(t, http.StatusBadRequest, status)
	})

	t.Run("unknown session", func(t *testing.T) {
		unknown := base64.RawURLEncoding.EncodeToString(make([]byte, protocolv2.PairingSessionIDSize))
		status, _ := doV2JSON(t, pt.client, http.MethodPost, "/v2/auth/pairing/hello", protocolv2.PairingHelloRequest{SessionID: unknown, Hello: pt.hello(t, pt.device)}, nil)
		require.Equal(t, http.StatusNotFound, status)
	})

	t.Run("credential ID already registered", func(t *testing.T) {
		registered := newTestDeviceKeys(t)
		registered.addToUser(t, pt.srv, pt.userID)

		status, _ := pt.sendHello(t, pt.hello(t, registered))
		require.Equal(t, http.StatusConflict, status)
	})

	t.Run("failures are audited against the session owner", func(t *testing.T) {
		rows := auditByType(t, pt.srv, pt.userID, db.AuditAuthPairingHello)
		require.NotEmpty(t, rows)
		for _, row := range rows {
			assert.Equal(t, db.AuditOutcomeFailure, row.Outcome)
		}
	})

	t.Run("session is still usable", func(t *testing.T) {
		status, out := pt.sendHello(t, pt.hello(t, pt.device))
		require.Equal(t, http.StatusOK, status, out)
	})
}

func TestServerV2PairingCompleteChecks(t *testing.T) {
	pt := newPairingTest(t, "v2-pairing-complete.db")
	pt.create(t)
	hello := pt.hello(t, pt.device)
	status, out := pt.sendHello(t, hello)
	require.Equal(t, http.StatusOK, status, out)
	status, _ = pt.sendNonce(t, hello)
	require.Equal(t, http.StatusOK, status)

	other := newTestDeviceKeys(t)
	type completeCase struct {
		build func(t *testing.T) protocolv2.PairingCompleteRequest
		err   string
	}
	cases := map[string]completeCase{
		"attestation for other keys": {err: "credentialPublicKeyHash does not match", build: func(t *testing.T) protocolv2.PairingCompleteRequest {
			return pt.completeRequest(t, pt.device, func(p *protocolv2.AttestationPayloadV2) {
				p.CredentialPublicKeyHash = other.public.Hash()
			})
		}},
		"attestation for another credential ID": {err: "credentialId does not match", build: func(t *testing.T) protocolv2.PairingCompleteRequest {
			return pt.completeRequest(t, pt.device, func(p *protocolv2.AttestationPayloadV2) {
				p.CredentialID = other.credentialID
			})
		}},
		"attestation for another user": {err: "userId does not match", build: func(t *testing.T) protocolv2.PairingCompleteRequest {
			return pt.completeRequest(t, pt.device, func(p *protocolv2.AttestationPayloadV2) {
				p.UserID = "user-bob"
			})
		}},
		"attestation for a passkey": {err: "credentialType must be device", build: func(t *testing.T) protocolv2.PairingCompleteRequest {
			return pt.completeRequest(t, pt.device, func(p *protocolv2.AttestationPayloadV2) {
				p.CredentialType = protocolv2.CredentialTypePasskey
			})
		}},
		"stale createdAt": {err: "createdAt", build: func(t *testing.T) protocolv2.PairingCompleteRequest {
			return pt.completeRequest(t, pt.device, func(p *protocolv2.AttestationPayloadV2) {
				p.CreatedAt = time.Now().Add(-5 * time.Minute).Unix()
			})
		}},
		"wrong epoch": {err: "wrappedKeyEpoch does not match", build: func(t *testing.T) protocolv2.PairingCompleteRequest {
			return pt.completeRequest(t, pt.device, func(p *protocolv2.AttestationPayloadV2) {
				p.WrappedKeyEpoch++
			})
		}},
		"signed by another anchor": {err: "attestation signature verification failed", build: func(t *testing.T) protocolv2.PairingCompleteRequest {
			req := pt.completeRequest(t, pt.device, nil)
			payload, err := protocolv2.ParseAttestationPayloadV2(req.AttestationPayload)
			require.NoError(t, err)
			otherAnchor := newTestAnchorKeyPair(t)
			req.AttestationSignatureEs384, req.AttestationSignatureMldsa87 = signHybridMessage(t, otherAnchor, protocolv2.CanonicalAttestationMessageV2(&payload))
			return req
		}},
		"v1 attestation": {err: "invalid attestationPayload", build: func(t *testing.T) protocolv2.PairingCompleteRequest {
			req := pt.completeRequest(t, pt.device, nil)
			payload := protocolv2.AttestationPayload{
				UserID:                  pt.userID,
				CredentialID:            pt.device.credentialID,
				CredentialPublicKeyHash: pt.device.public.Hash(),
				WrappedKeyEpoch:         1,
				CreatedAt:               time.Now().Unix(),
			}
			req.AttestationPayload = payload.CanonicalBody()
			req.AttestationSignatureEs384, req.AttestationSignatureMldsa87 = signHybridMessage(t, pt.anchor, protocolv2.CanonicalAttestationMessage(&payload))
			return req
		}},
		"passkey envelope": {err: "not a device envelope", build: func(t *testing.T) protocolv2.PairingCompleteRequest {
			req := pt.completeRequest(t, pt.device, nil)
			env := protocolv2.WrappedPrimaryKeyEnvelope{
				V:          protocolv2.WrappedPrimaryKeyVersion,
				Nonce:      base64.RawURLEncoding.EncodeToString(make([]byte, 12)),
				Ciphertext: base64.RawURLEncoding.EncodeToString(make([]byte, 48)),
			}
			var err error
			req.WrappedPrimaryKey, err = env.Encode()
			require.NoError(t, err)
			return req
		}},
		"invalid anchor envelope": {err: "invalid wrappedAnchorKey", build: func(t *testing.T) protocolv2.PairingCompleteRequest {
			req := pt.completeRequest(t, pt.device, nil)
			req.WrappedAnchorKey = "not-an-envelope"
			return req
		}},
		"display name too long": {err: "displayName is too long", build: func(t *testing.T) protocolv2.PairingCompleteRequest {
			req := pt.completeRequest(t, pt.device, nil)
			req.DisplayName = strings.Repeat("a", protocolv2.MaxDeviceNameLength+1)
			return req
		}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			status, out := pt.complete(t, tc.build(t))
			require.Equal(t, http.StatusBadRequest, status)
			assert.Contains(t, out["error"], tc.err)
		})
	}

	// The failures rolled back, so the session is still at the nonce step and a valid completion works
	req := pt.completeRequest(t, pt.device, nil)
	req.DisplayName = "  Work iPhone  "
	status, out = pt.complete(t, req)
	require.Equal(t, http.StatusOK, status, out)

	cred, err := pt.srv.db.AuthStore().GetCredentialForUser(t.Context(), pt.userID, pt.device.credentialID)
	require.NoError(t, err)
	require.NotNil(t, cred)
	assert.Equal(t, "Work iPhone", cred.DisplayName)

	// The failures are audited against the user
	rows := auditByType(t, pt.srv, pt.userID, db.AuditAuthPairingComplete)
	var failures, successes int
	for _, row := range rows {
		switch row.Outcome {
		case db.AuditOutcomeFailure:
			failures++
		case db.AuditOutcomeSuccess:
			successes++
		}
	}
	assert.Positive(t, failures)
	assert.Equal(t, 1, successes)
}

func TestServerV2PairingExpiryAndCancel(t *testing.T) {
	pt := newPairingTest(t, "v2-pairing-expiry.db")

	t.Run("expired session", func(t *testing.T) {
		pt.create(t)
		_, err := pt.srv.db.Exec(t.Context(), `UPDATE v2_pairing_sessions SET expires_at = $1 WHERE id = $2`, time.Now().Add(-time.Second).Unix(), pt.sessionID)
		require.NoError(t, err)

		status, out := pt.deviceStatus(t, pt.sessionID)
		require.Equal(t, http.StatusOK, status, out)
		assert.Equal(t, protocolv2.PairingStatusExpired, out["status"])

		status, _ = pt.sendHello(t, pt.hello(t, pt.device))
		require.Equal(t, http.StatusConflict, status)
	})

	t.Run("a new session cancels the open one", func(t *testing.T) {
		pt.create(t)
		first := pt.sessionID
		pt.create(t)

		status, out := pt.deviceStatus(t, first)
		require.Equal(t, http.StatusOK, status, out)
		assert.Equal(t, protocolv2.PairingStatusCanceled, out["status"])
	})

	t.Run("cancel", func(t *testing.T) {
		pt.create(t)

		status, out := doV2JSON(t, pt.client, http.MethodPost, "/v2/auth/pairing/cancel", protocolv2.PairingCancelRequest{SessionID: pt.sessionID}, withCookie(pt.cookie))
		require.Equal(t, http.StatusOK, status, out)

		status, out = pt.deviceStatus(t, pt.sessionID)
		require.Equal(t, http.StatusOK, status, out)
		assert.Equal(t, protocolv2.PairingStatusCanceled, out["status"])

		status, _ = pt.sendHello(t, pt.hello(t, pt.device))
		require.Equal(t, http.StatusConflict, status)

		status, _ = doV2JSON(t, pt.client, http.MethodPost, "/v2/auth/pairing/cancel", protocolv2.PairingCancelRequest{SessionID: pt.sessionID}, withCookie(pt.cookie))
		require.Equal(t, http.StatusConflict, status)

		rows := auditByType(t, pt.srv, pt.userID, db.AuditAuthPairingCancel)
		require.Len(t, rows, 1)
		assert.Equal(t, db.AuditOutcomeSuccess, rows[0].Outcome)
	})

	t.Run("invalid session IDs", func(t *testing.T) {
		status, _ := pt.deviceStatus(t, "not-a-session")
		require.Equal(t, http.StatusBadRequest, status)

		unknown := base64.RawURLEncoding.EncodeToString(make([]byte, protocolv2.PairingSessionIDSize))
		status, _ = pt.deviceStatus(t, unknown)
		require.Equal(t, http.StatusNotFound, status)
	})
}

func TestServerV2PairingOtherUsersSession(t *testing.T) {
	pt := newPairingTest(t, "v2-pairing-other-user.db")
	pt.create(t)
	hello := pt.hello(t, pt.device)
	status, out := pt.sendHello(t, hello)
	require.Equal(t, http.StatusOK, status, out)

	// Bob can't see or drive Alice's session
	bobCookie, _ := seedV2SessionCookie(t, pt.srv, "user-bob", "Bob")
	_ = seedV2AnchorForUser(t, pt.srv, "user-bob")

	status, _ = doV2JSON(t, pt.client, http.MethodGet, "/v2/auth/pairing/"+pt.sessionID, nil, withCookie(bobCookie))
	require.Equal(t, http.StatusNotFound, status)

	status, _ = doV2JSON(t, pt.client, http.MethodPost, "/v2/auth/pairing/nonce", protocolv2.PairingNonceRequest{
		SessionID: pt.sessionID,
		Nonce:     base64.RawURLEncoding.EncodeToString(make([]byte, protocolv2.PairingNonceSize)),
		NonceMAC:  base64.RawURLEncoding.EncodeToString(make([]byte, protocolv2.PairingMACSize)),
	}, withCookie(bobCookie))
	require.Equal(t, http.StatusNotFound, status)

	status, _ = doV2JSON(t, pt.client, http.MethodPost, "/v2/auth/pairing/complete", pt.completeRequest(t, pt.device, nil), withCookie(bobCookie))
	require.Equal(t, http.StatusNotFound, status)

	status, _ = doV2JSON(t, pt.client, http.MethodPost, "/v2/auth/pairing/cancel", protocolv2.PairingCancelRequest{SessionID: pt.sessionID}, withCookie(bobCookie))
	require.Equal(t, http.StatusNotFound, status)

	// Alice's session is untouched
	status, out = doV2JSON(t, pt.client, http.MethodGet, "/v2/auth/pairing/"+pt.sessionID, nil, withCookie(pt.cookie))
	require.Equal(t, http.StatusOK, status, out)
	assert.Equal(t, protocolv2.PairingStatusHello, out["status"])

	// The authenticated routes need a session
	status, _ = doV2JSON(t, pt.client, http.MethodGet, "/v2/auth/pairing/"+pt.sessionID, nil, nil)
	require.Equal(t, http.StatusUnauthorized, status)
	status, _ = doV2JSON(t, pt.client, http.MethodPost, "/v2/auth/pairing/create", protocolv2.PairingCreateRequest{Server: pt.serverURL()}, nil)
	require.Equal(t, http.StatusUnauthorized, status)
}

func TestServerV2PairingCreateChecks(t *testing.T) {
	setTestConfig(t, "v2-pairing-create.db")
	srv := newTestServer(t, nil, nil, nil)
	startTestServer(t, srv)
	client := clientForListener(srv.appListener)

	cookie, _ := seedV2SessionCookie(t, srv, "user-alice", "Alice")
	create := func(t *testing.T, server string) int {
		t.Helper()
		status, _ := doV2JSON(t, client, http.MethodPost, "/v2/auth/pairing/create", protocolv2.PairingCreateRequest{Server: server}, withCookie(cookie))
		return status
	}
	serverURL := fmt.Sprintf("https://localhost:%d", testServerPort)

	t.Run("needs an anchor", func(t *testing.T) {
		require.Equal(t, http.StatusConflict, create(t, serverURL))
	})

	_ = seedV2AnchorForUser(t, srv, "user-alice")

	t.Run("invalid server", func(t *testing.T) {
		require.Equal(t, http.StatusBadRequest, create(t, "http://vault.example.com"))
		require.Equal(t, http.StatusBadRequest, create(t, "https://vault.example.com/?q=1"))
	})

	t.Run("refused during a passkey registration", func(t *testing.T) {
		_, err := db.ExecuteInTransaction(t.Context(), srv.db, 20*time.Second, func(ctx context.Context, tx *db.DbTx) (*db.AuthChallenge, error) {
			return tx.AuthStore().BeginChallenge(ctx, "add-credential", "user-alice", "test-challenge", time.Now().Add(time.Minute), nil)
		})
		require.NoError(t, err)

		require.Equal(t, http.StatusConflict, create(t, serverURL))
	})
}

func TestServerV2PairingPollingRateLimit(t *testing.T) {
	pt := newPairingTest(t, "v2-pairing-poll.db")
	pt.create(t)

	// Both clients poll every 1 to 2 seconds, which is more than the auth rate limit allows
	for i := range authRateLimitRPM + 10 {
		status, _ := pt.deviceStatus(t, pt.sessionID)
		require.Equal(t, http.StatusOK, status, "poll %d", i)
		status, _ = doV2JSON(t, pt.client, http.MethodGet, "/v2/auth/pairing/"+pt.sessionID, nil, withCookie(pt.cookie))
		require.Equal(t, http.StatusOK, status, "poll %d", i)
	}
}
