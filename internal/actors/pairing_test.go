package actors

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/italypaleale/revaulter/internal/db"
	"github.com/italypaleale/revaulter/internal/protocolv2"
)

func newTestPairingSessionID(t *testing.T) string {
	t.Helper()

	id, err := NewPairingSessionID()
	require.NoError(t, err)

	return id
}

func testPairingHello(credentialID string) protocolv2.PairingHello {
	return protocolv2.PairingHello{
		DeviceName:   "iPhone",
		CredentialID: credentialID,
		PublicKeys: protocolv2.DevicePublicKeys{
			SignP256:    "sign-p256",
			KaP256:      "ka-p256",
			SignMldsa65: "sign-mldsa65",
			KemMlkem768: "kem-mlkem768",
		},
	}
}

func testPairingCredential(userID string, credentialID string) db.AddCredentialInput {
	return db.AddCredentialInput{
		UserID:          userID,
		CredentialID:    credentialID,
		DisplayName:     "iPhone",
		CredentialType:  protocolv2.CredentialTypeDevice,
		PublicKey:       `{}`,
		WrappedKeyEpoch: 1,
	}
}

// openTestPairingSession opens a session and moves it to the nonce step
func openTestPairingSession(t *testing.T, pairing PairingClient, credentialID string) *PairingSession {
	t.Helper()

	p, err := pairing.Create(t.Context(), newTestPairingSessionID(t), "https://vault.example.com", protocolv2.PairingTTL, nil)
	require.NoError(t, err)
	_, err = pairing.Hello(t.Context(), p.SessionID, testPairingHello(credentialID), nil)
	require.NoError(t, err)
	p, err = pairing.Nonce(t.Context(), p.SessionID, "nonce", "nonce-mac")
	require.NoError(t, err)

	return p
}

func TestPairingActor(t *testing.T) {
	const userID = "user-pairing"
	h := newTestHost(t, newTestDB(t, userID), ":memory:")
	pairing := h.Pairing(userID)

	t.Run("full flow", func(t *testing.T) {
		p, err := pairing.Create(t.Context(), newTestPairingSessionID(t), "https://vault.example.com", protocolv2.PairingTTL, signupTestAudit(db.AuditAuthPairingCreate, userID))
		require.NoError(t, err)
		assert.Equal(t, protocolv2.PairingStatusCreated, p.Status)
		assert.Equal(t, userID, p.UserID)
		assert.Equal(t, "https://vault.example.com", p.Server)
		assert.WithinDuration(t, time.Now().Add(protocolv2.PairingTTL), p.ExpiresAt, 5*time.Second)
		assert.Len(t, auditEvents(t, h, userID, db.AuditAuthPairingCreate), 1)

		open, err := pairing.IsOpen(t.Context())
		require.NoError(t, err)
		assert.True(t, open)

		// The session is found only with its ID
		got, err := pairing.Get(t.Context(), p.SessionID)
		require.NoError(t, err)
		require.NotNil(t, got)
		got, err = pairing.Get(t.Context(), "other")
		require.NoError(t, err)
		assert.Nil(t, got)
		_, err = pairing.Hello(t.Context(), "other", testPairingHello("device-flow"), nil)
		require.ErrorIs(t, err, ErrPairingSessionNotFound)

		// The hello is accepted once
		got, err = pairing.Hello(t.Context(), p.SessionID, testPairingHello("device-flow"), signupTestAudit(db.AuditAuthPairingHello, userID))
		require.NoError(t, err)
		assert.Equal(t, protocolv2.PairingStatusHello, got.Status)
		require.NotNil(t, got.Hello)
		assert.Equal(t, "device-flow", got.Hello.CredentialID)
		assert.Len(t, auditEvents(t, h, userID, db.AuditAuthPairingHello), 1)
		_, err = pairing.Hello(t.Context(), p.SessionID, testPairingHello("device-other"), nil)
		require.ErrorIs(t, err, ErrPairingSessionState)

		// So is the nonce
		got, err = pairing.Nonce(t.Context(), p.SessionID, "nonce", "nonce-mac")
		require.NoError(t, err)
		assert.Equal(t, protocolv2.PairingStatusNonce, got.Status)
		assert.Equal(t, "nonce", got.Nonce)
		assert.Equal(t, "nonce-mac", got.NonceMAC)
		_, err = pairing.Nonce(t.Context(), p.SessionID, "nonce-2", "nonce-mac-2")
		require.ErrorIs(t, err, ErrPairingSessionState)

		// Completing adds the credential and closes the session
		got, err = pairing.Complete(t.Context(), p.SessionID, testPairingCredential(userID, "device-flow"), signupTestAudit(db.AuditAuthPairingComplete, userID))
		require.NoError(t, err)
		assert.Equal(t, protocolv2.PairingStatusCompleted, got.Status)
		assert.Len(t, auditEvents(t, h, userID, db.AuditAuthPairingComplete), 1)

		cred, err := h.db.AuthStore().GetCredentialForUser(t.Context(), userID, "device-flow")
		require.NoError(t, err)
		require.NotNil(t, cred)
		assert.Equal(t, protocolv2.CredentialTypeDevice, cred.CredentialType)

		_, err = pairing.Complete(t.Context(), p.SessionID, testPairingCredential(userID, "device-flow"), nil)
		require.ErrorIs(t, err, ErrPairingSessionState)

		// The completed session can still be read, but it's no longer open
		got, err = pairing.Get(t.Context(), p.SessionID)
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, protocolv2.PairingStatusCompleted, got.ReportedStatus(time.Now()))
		open, err = pairing.IsOpen(t.Context())
		require.NoError(t, err)
		assert.False(t, open)
	})

	t.Run("steps can't be skipped", func(t *testing.T) {
		p, err := pairing.Create(t.Context(), newTestPairingSessionID(t), "https://vault.example.com", protocolv2.PairingTTL, nil)
		require.NoError(t, err)

		_, err = pairing.Nonce(t.Context(), p.SessionID, "nonce", "nonce-mac")
		require.ErrorIs(t, err, ErrPairingSessionState)
		_, err = pairing.Complete(t.Context(), p.SessionID, testPairingCredential(userID, "device-skip"), nil)
		require.ErrorIs(t, err, ErrPairingSessionState)

		_, err = pairing.Hello(t.Context(), p.SessionID, testPairingHello("device-skip"), nil)
		require.NoError(t, err)
		_, err = pairing.Complete(t.Context(), p.SessionID, testPairingCredential(userID, "device-skip"), nil)
		require.ErrorIs(t, err, ErrPairingSessionState)
	})

	t.Run("a new session replaces the previous one", func(t *testing.T) {
		first, err := pairing.Create(t.Context(), newTestPairingSessionID(t), "https://vault.example.com", protocolv2.PairingTTL, nil)
		require.NoError(t, err)
		second, err := pairing.Create(t.Context(), newTestPairingSessionID(t), "https://vault.example.com", protocolv2.PairingTTL, nil)
		require.NoError(t, err)
		require.NotEqual(t, first.SessionID, second.SessionID)

		got, err := pairing.Get(t.Context(), first.SessionID)
		require.NoError(t, err)
		assert.Nil(t, got)
		_, err = pairing.Hello(t.Context(), first.SessionID, testPairingHello("device-replaced"), nil)
		require.ErrorIs(t, err, ErrPairingSessionNotFound)
	})

	t.Run("completion must add the device from the hello", func(t *testing.T) {
		p := openTestPairingSession(t, pairing, "device-mismatch")

		_, err := pairing.Complete(t.Context(), p.SessionID, testPairingCredential(userID, "device-other"), nil)
		require.Error(t, err)

		passkey := testPairingCredential(userID, "device-mismatch")
		passkey.CredentialType = protocolv2.CredentialTypePasskey
		_, err = pairing.Complete(t.Context(), p.SessionID, passkey, nil)
		require.Error(t, err)

		// The session is still waiting for a completion
		got, err := pairing.Complete(t.Context(), p.SessionID, testPairingCredential(userID, "device-mismatch"), nil)
		require.NoError(t, err)
		assert.Equal(t, protocolv2.PairingStatusCompleted, got.Status)
	})

	t.Run("a failed completion leaves the session open", func(t *testing.T) {
		// The credential from the full flow is already registered
		p := openTestPairingSession(t, pairing, "device-flow")
		_, err := pairing.Complete(t.Context(), p.SessionID, testPairingCredential(userID, "device-flow"), signupTestAudit(db.AuditAuthPairingComplete, userID))
		require.ErrorIs(t, err, db.ErrCredentialAlreadyExists)

		// The epoch the device was wrapped for must still be the user's
		p = openTestPairingSession(t, pairing, "device-epoch")
		stale := testPairingCredential(userID, "device-epoch")
		stale.WrappedKeyEpoch = 0
		_, err = pairing.Complete(t.Context(), p.SessionID, stale, nil)
		require.ErrorIs(t, err, db.ErrWrappedKeyEpochChanged)

		got, err := pairing.Get(t.Context(), p.SessionID)
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, protocolv2.PairingStatusNonce, got.Status)

		// Neither failure wrote a success row
		assert.Len(t, auditEvents(t, h, userID, db.AuditAuthPairingComplete), 1)
	})

	t.Run("cancel", func(t *testing.T) {
		p, err := pairing.Create(t.Context(), newTestPairingSessionID(t), "https://vault.example.com", protocolv2.PairingTTL, nil)
		require.NoError(t, err)

		got, err := pairing.Cancel(t.Context(), p.SessionID, signupTestAudit(db.AuditAuthPairingCancel, userID))
		require.NoError(t, err)
		assert.Equal(t, protocolv2.PairingStatusCanceled, got.Status)
		assert.Len(t, auditEvents(t, h, userID, db.AuditAuthPairingCancel), 1)

		_, err = pairing.Cancel(t.Context(), p.SessionID, nil)
		require.ErrorIs(t, err, ErrPairingSessionState)
		_, err = pairing.Hello(t.Context(), p.SessionID, testPairingHello("device-canceled"), nil)
		require.ErrorIs(t, err, ErrPairingSessionState)
	})

	t.Run("expired session", func(t *testing.T) {
		p, err := pairing.Create(t.Context(), newTestPairingSessionID(t), "https://vault.example.com", -time.Second, nil)
		require.NoError(t, err)
		assert.Equal(t, protocolv2.PairingStatusExpired, p.ReportedStatus(time.Now()))

		open, err := pairing.IsOpen(t.Context())
		require.NoError(t, err)
		assert.False(t, open)

		_, err = pairing.Hello(t.Context(), p.SessionID, testPairingHello("device-expired"), nil)
		require.ErrorIs(t, err, ErrPairingSessionState)
		_, err = pairing.Cancel(t.Context(), p.SessionID, nil)
		require.ErrorIs(t, err, ErrPairingSessionState)
	})

	t.Run("session ID is required", func(t *testing.T) {
		_, err := pairing.Create(t.Context(), "", "https://vault.example.com", protocolv2.PairingTTL, nil)
		require.Error(t, err)
	})

	t.Run("invalid user IDs", func(t *testing.T) {
		for _, id := range []string{"", "a/b"} {
			_, err := h.Pairing(id).Create(t.Context(), newTestPairingSessionID(t), "https://vault.example.com", protocolv2.PairingTTL, nil)
			require.Error(t, err)
			got, err := h.Pairing(id).Get(t.Context(), "session")
			require.NoError(t, err)
			assert.Nil(t, got)
			_, err = h.Pairing(id).Hello(t.Context(), "session", testPairingHello("device"), nil)
			require.ErrorIs(t, err, ErrPairingSessionNotFound)
		}
	})
}

func TestPairingActorCleanup(t *testing.T) {
	h := newTestHost(t, newTestDB(t), ":memory:")

	// A session that expired just under the retention period ago, so the cleanup alarm fires in a second
	_, err := h.Pairing("user-pairing-cleanup").Create(t.Context(), newTestPairingSessionID(t), "https://vault.example.com", -pairingRetention+time.Second, nil)
	require.NoError(t, err)
	require.Equal(t, 1, countActorStates(t, h, actorTypePairing))

	require.Eventually(t, func() bool {
		return countActorStates(t, h, actorTypePairing) == 0
	}, 15*time.Second, 100*time.Millisecond, "the expired pairing session was not deleted")
}
