package server

import (
	"context"
	"encoding/base64"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/italypaleale/revaulter/internal/db"
	"github.com/italypaleale/revaulter/internal/protocolv2"
)

// deviceLoginBegin starts a device login and returns the challenge ID and challenge
func deviceLoginBegin(t *testing.T, client *http.Client, userID string, credentialID string) (string, string) {
	t.Helper()

	status, out := doV2JSON(t, client, http.MethodPost, "/v2/auth/device/login/begin", protocolv2.DeviceLoginBeginRequest{
		UserID:       userID,
		CredentialID: credentialID,
	}, nil)
	require.Equal(t, http.StatusOK, status, out)

	challengeID, _ := out["challengeId"].(string)
	challenge, _ := out["challenge"].(string)
	require.NotEmpty(t, challengeID)
	require.NotEmpty(t, challenge)

	return challengeID, challenge
}

// signDeviceLogin signs the login message for a challenge with the device's keys
func signDeviceLogin(t *testing.T, device *testDeviceKeys, userID string, challengeID string, challenge string) protocolv2.DeviceLoginFinishRequest {
	t.Helper()

	sigP256, sigMldsa65 := device.sign(t, protocolv2.CanonicalDeviceLoginMessage(&protocolv2.DeviceLoginPayload{
		Challenge:    challenge,
		CredentialID: device.credentialID,
		UserID:       userID,
		V:            protocolv2.DeviceLoginVersion,
	}))

	return protocolv2.DeviceLoginFinishRequest{
		ChallengeID:      challengeID,
		CredentialID:     device.credentialID,
		SignatureP256:    sigP256,
		SignatureMldsa65: sigMldsa65,
	}
}

func TestServerV2DeviceLogin(t *testing.T) {
	setTestConfig(t, "v2-device-login.db")
	srv := newTestServer(t, nil, nil, nil)
	startTestServer(t, srv)
	client := clientForListener(srv.appListener)

	_, _ = seedV2SessionCookie(t, srv, "user-alice", "Alice")
	device := newTestDeviceKeys(t)
	device.addToUser(t, srv, "user-alice")

	finish := func(t *testing.T, req protocolv2.DeviceLoginFinishRequest) (int, map[string]any) {
		t.Helper()
		return doV2JSON(t, client, http.MethodPost, "/v2/auth/device/login/finish", req, nil)
	}

	t.Run("logs in and returns a bearer token", func(t *testing.T) {
		// Clear last_used_at so the test can see the login set it
		_, err := srv.db.Exec(t.Context(), `UPDATE v2_user_credentials SET last_used_at = 0 WHERE credential_id = $1`, device.credentialID)
		require.NoError(t, err)

		// No Origin header and no cookie, as the native app sends
		challengeID, challenge := deviceLoginBegin(t, client, "user-alice", device.credentialID)
		status, out := finish(t, signDeviceLogin(t, device, "user-alice", challengeID, challenge))
		require.Equal(t, http.StatusOK, status, out)

		assert.Equal(t, true, out["authenticated"])
		assert.Equal(t, "user-alice", out["userId"])
		assert.Equal(t, "device-wrapped-primary-key", out["wrappedPrimaryKey"])
		assert.Equal(t, testValidWrappedAnchorEnvelope(t), out["wrappedAnchorKey"])
		assert.Equal(t, false, out["wrappedKeyStale"])
		expiresAt, _ := out["sessionExpiresAt"].(float64)
		assert.Greater(t, int64(expiresAt), time.Now().Unix())

		token, _ := out["sessionToken"].(string)
		require.NotEmpty(t, token)

		// The token authenticates as a bearer token
		status, out = doV2JSON(t, client, http.MethodGet, "/v2/auth/session", nil, withBearer(token))
		require.Equal(t, http.StatusOK, status, out)
		assert.Equal(t, "user-alice", out["userId"])

		// The login is recorded against the device credential
		rows := auditByType(t, srv, "user-alice", db.AuditAuthDeviceLoginFinish)
		require.Len(t, rows, 1)
		assert.Equal(t, db.AuditOutcomeSuccess, rows[0].Outcome)
		require.NotNil(t, rows[0].CredentialID)
		assert.Equal(t, device.credentialID, *rows[0].CredentialID)

		// The login updated last_used_at
		cred, err := srv.db.AuthStore().GetCredentialForUser(t.Context(), "user-alice", device.credentialID)
		require.NoError(t, err)
		require.NotNil(t, cred)
		assert.Positive(t, cred.LastUsedAt)
	})

	t.Run("challenge can't be replayed", func(t *testing.T) {
		challengeID, challenge := deviceLoginBegin(t, client, "user-alice", device.credentialID)
		req := signDeviceLogin(t, device, "user-alice", challengeID, challenge)

		status, out := finish(t, req)
		require.Equal(t, http.StatusOK, status, out)

		status, _ = finish(t, req)
		require.Equal(t, http.StatusConflict, status)
	})

	t.Run("expired challenge is refused", func(t *testing.T) {
		challengeID, challenge := deviceLoginBegin(t, client, "user-alice", device.credentialID)
		_, err := srv.db.Exec(t.Context(), `UPDATE v2_auth_challenges SET expires_at = $1 WHERE id = $2`, time.Now().Add(-time.Minute).Unix(), challengeID)
		require.NoError(t, err)

		status, _ := finish(t, signDeviceLogin(t, device, "user-alice", challengeID, challenge))
		require.Equal(t, http.StatusConflict, status)
	})

	t.Run("each signature is checked", func(t *testing.T) {
		other := newTestDeviceKeys(t)

		challengeID, challenge := deviceLoginBegin(t, client, "user-alice", device.credentialID)
		req := signDeviceLogin(t, device, "user-alice", challengeID, challenge)
		forged := signDeviceLogin(t, other, "user-alice", challengeID, challenge)
		req.SignatureP256 = forged.SignatureP256
		status, _ := finish(t, req)
		require.Equal(t, http.StatusUnauthorized, status)

		challengeID, challenge = deviceLoginBegin(t, client, "user-alice", device.credentialID)
		req = signDeviceLogin(t, device, "user-alice", challengeID, challenge)
		forged = signDeviceLogin(t, other, "user-alice", challengeID, challenge)
		req.SignatureMldsa65 = forged.SignatureMldsa65
		status, _ = finish(t, req)
		require.Equal(t, http.StatusUnauthorized, status)
	})

	t.Run("signature must cover the issued challenge", func(t *testing.T) {
		challengeID, _ := deviceLoginBegin(t, client, "user-alice", device.credentialID)
		otherChallenge := base64.RawURLEncoding.EncodeToString(make([]byte, deviceLoginChallengeSize))
		status, _ := finish(t, signDeviceLogin(t, device, "user-alice", challengeID, otherChallenge))
		require.Equal(t, http.StatusUnauthorized, status)
	})

	t.Run("credential must match the challenge", func(t *testing.T) {
		other := newTestDeviceKeys(t)
		other.addToUser(t, srv, "user-alice")

		// The challenge was issued for device, so other can't use it even with valid signatures
		challengeID, challenge := deviceLoginBegin(t, client, "user-alice", device.credentialID)
		status, _ := finish(t, signDeviceLogin(t, other, "user-alice", challengeID, challenge))
		require.Equal(t, http.StatusUnauthorized, status)
	})

	t.Run("unknown user or credential looks the same at begin", func(t *testing.T) {
		stranger := newTestDeviceKeys(t)

		challengeID, challenge := deviceLoginBegin(t, client, "user-nobody", stranger.credentialID)
		status, _ := finish(t, signDeviceLogin(t, stranger, "user-nobody", challengeID, challenge))
		require.Equal(t, http.StatusUnauthorized, status)

		challengeID, challenge = deviceLoginBegin(t, client, "user-alice", stranger.credentialID)
		status, _ = finish(t, signDeviceLogin(t, stranger, "user-alice", challengeID, challenge))
		require.Equal(t, http.StatusUnauthorized, status)
	})

	t.Run("passkey credentials can't log in as devices", func(t *testing.T) {
		// A passkey whose ID happens to have the device format
		impostor := newTestDeviceKeys(t)
		_, err := db.ExecuteInTransaction(t.Context(), srv.db, 20*time.Second, func(ctx context.Context, tx *db.DbTx) (struct{}, error) {
			return struct{}{}, tx.AuthStore().AddCredential(ctx, db.AddCredentialInput{
				UserID:       "user-alice",
				CredentialID: impostor.credentialID,
				DisplayName:  "Passkey",
				PublicKey:    impostor.publicKeyJSON(t),
			})
		})
		require.NoError(t, err)

		challengeID, challenge := deviceLoginBegin(t, client, "user-alice", impostor.credentialID)
		status, _ := finish(t, signDeviceLogin(t, impostor, "user-alice", challengeID, challenge))
		require.Equal(t, http.StatusUnauthorized, status)
	})

	t.Run("failures are audited", func(t *testing.T) {
		// Failure rows have no actor, so query by event type only
		all, _, err := srv.db.AuditStore().List(t.Context(), db.AuditFilter{EventType: db.AuditAuthDeviceLoginFinish}, 50, "")
		require.NoError(t, err)

		var failures int
		for _, ev := range all {
			if ev.Outcome == db.AuditOutcomeFailure {
				failures++
			}
		}
		assert.Positive(t, failures)
	})
}

func TestServerV2DeviceLoginInvalidInput(t *testing.T) {
	setTestConfig(t, "v2-device-login-input.db")
	srv := newTestServer(t, nil, nil, nil)
	startTestServer(t, srv)
	client := clientForListener(srv.appListener)

	device := newTestDeviceKeys(t)

	beginCases := map[string]protocolv2.DeviceLoginBeginRequest{
		"empty userId":                {UserID: "", CredentialID: device.credentialID},
		"long userId":                 {UserID: string(make([]byte, maxDeviceLoginUserIDLength+1)), CredentialID: device.credentialID},
		"empty credentialId":          {UserID: "user-alice"},
		"short credentialId":          {UserID: "user-alice", CredentialID: base64.RawURLEncoding.EncodeToString([]byte("short"))},
		"padded credentialId":         {UserID: "user-alice", CredentialID: base64.URLEncoding.EncodeToString(make([]byte, protocolv2.DeviceCredentialIDSize))},
		"passkey-shaped credentialId": {UserID: "user-alice", CredentialID: "cred-user-alice"},
	}
	for name, req := range beginCases {
		t.Run("begin "+name, func(t *testing.T) {
			status, _ := doV2JSON(t, client, http.MethodPost, "/v2/auth/device/login/begin", req, nil)
			require.Equal(t, http.StatusBadRequest, status)
		})
	}

	validP256 := base64.RawURLEncoding.EncodeToString(make([]byte, protocolv2.P256SignatureSize))
	validMldsa65 := base64.RawURLEncoding.EncodeToString(make([]byte, protocolv2.MLDSA65SignatureSize))
	finishCases := map[string]protocolv2.DeviceLoginFinishRequest{
		"missing challengeId":     {CredentialID: device.credentialID, SignatureP256: validP256, SignatureMldsa65: validMldsa65},
		"missing credentialId":    {ChallengeID: "x", SignatureP256: validP256, SignatureMldsa65: validMldsa65},
		"short P-256 signature":   {ChallengeID: "x", CredentialID: device.credentialID, SignatureP256: validP256[:20], SignatureMldsa65: validMldsa65},
		"short ML-DSA signature":  {ChallengeID: "x", CredentialID: device.credentialID, SignatureP256: validP256, SignatureMldsa65: validMldsa65[:20]},
		"non-base64url signature": {ChallengeID: "x", CredentialID: device.credentialID, SignatureP256: "!!!", SignatureMldsa65: validMldsa65},
	}
	for name, req := range finishCases {
		t.Run("finish "+name, func(t *testing.T) {
			status, _ := doV2JSON(t, client, http.MethodPost, "/v2/auth/device/login/finish", req, nil)
			require.Equal(t, http.StatusBadRequest, status)
		})
	}
}

func TestServerV2DeviceLoginRateLimitsWrappedKey(t *testing.T) {
	setTestConfig(t, "v2-device-login-limit.db")
	srv := newTestServer(t, nil, nil, nil)
	startTestServer(t, srv)
	client := clientForListener(srv.appListener)

	_, _ = seedV2SessionCookie(t, srv, "user-alice", "Alice")
	device := newTestDeviceKeys(t)
	device.addToUser(t, srv, "user-alice")

	// The wrapped-key limiter allows 4 deliveries per user in its window
	for range 4 {
		challengeID, challenge := deviceLoginBegin(t, client, "user-alice", device.credentialID)
		status, out := doV2JSON(t, client, http.MethodPost, "/v2/auth/device/login/finish", signDeviceLogin(t, device, "user-alice", challengeID, challenge), nil)
		require.Equal(t, http.StatusOK, status, out)
	}

	challengeID, challenge := deviceLoginBegin(t, client, "user-alice", device.credentialID)
	status, out := doV2JSON(t, client, http.MethodPost, "/v2/auth/device/login/finish", signDeviceLogin(t, device, "user-alice", challengeID, challenge), nil)
	require.Equal(t, http.StatusTooManyRequests, status)
	assert.Empty(t, out["sessionToken"])
}
