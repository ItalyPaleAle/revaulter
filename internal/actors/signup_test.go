package actors

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/italypaleale/revaulter/internal/db"
)

func TestSignupActor(t *testing.T) {
	h := newTestHost(t, newTestDB(t), ":memory:")

	t.Run("full signup", func(t *testing.T) {
		const (
			signupID = "signup-full"
			userID   = "user-signup-full"
		)
		signup := h.Signup(signupID)

		err := signup.Begin(t.Context(), Signup{
			UserID:         userID,
			DisplayName:    "Alice",
			WebAuthnUserID: signupID,
			Session:        []byte(`{"challenge":"c1"}`),
			ExpiresAt:      time.Now().Add(time.Minute),
		})
		require.NoError(t, err)

		got, err := signup.Get(t.Context())
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, SignupPhaseBegun, got.Phase)
		assert.Equal(t, userID, got.UserID)
		assert.JSONEq(t, `{"challenge":"c1"}`, string(got.Session))
		assert.Nil(t, got.Credential)

		// Signing in requires a registered passkey
		_, err = signup.Login(t.Context(), "cred-1", 2, nil)
		require.ErrorIs(t, err, ErrSignupNotFound)

		// Register the passkey
		got, err = signup.Register(t.Context(), SignupCredential{ID: "cred-1", PublicKey: `{}`, SignCount: 1}, signupTestAudit(db.AuditAuthRegisterFinish, userID))
		require.NoError(t, err)
		assert.Equal(t, SignupPhaseRegistered, got.Phase)
		assert.Empty(t, got.Session)
		require.NotNil(t, got.Credential)
		assert.Equal(t, "cred-1", got.Credential.ID)
		assert.WithinDuration(t, time.Now().Add(SignupRegisteredTTL), got.ExpiresAt, time.Minute)
		assert.Len(t, auditEvents(t, h, userID, db.AuditAuthRegisterFinish), 1)

		// The registration challenge can be used once only
		_, err = signup.Register(t.Context(), SignupCredential{ID: "cred-2", PublicKey: `{}`}, nil)
		require.ErrorIs(t, err, ErrSignupNotFound)

		// Sign in with the passkey
		_, err = signup.Login(t.Context(), "cred-other", 2, nil)
		require.ErrorIs(t, err, ErrSignupNotFound)
		got, err = signup.Login(t.Context(), "cred-1", 5, signupTestAudit(db.AuditAuthLoginFinish, userID))
		require.NoError(t, err)
		assert.EqualValues(t, 5, got.Credential.SignCount)
		assert.Len(t, auditEvents(t, h, userID, db.AuditAuthLoginFinish), 1)

		// The user is not in the database until the signup is finalized
		user, err := h.db.AuthStore().GetUserByID(t.Context(), userID)
		require.NoError(t, err)
		assert.Nil(t, user)

		// The user ID in the input is replaced with the signup's
		_, err = signup.Finalize(t.Context(), db.FinalizeSignupInput{
			UserID:                "ignored",
			WrappedPrimaryKey:     "wrapped-key",
			RequestEncEcdhPubkey:  "ecdh",
			RequestEncMlkemPubkey: "mlkem",
			PubkeyBundleVersion:   2,
		}, signupTestAudit(db.AuditAuthFinalizeSignup, userID))
		require.NoError(t, err)

		user, err = h.db.AuthStore().GetUserByID(t.Context(), userID)
		require.NoError(t, err)
		require.NotNil(t, user)
		assert.True(t, user.Ready)
		assert.Equal(t, "Alice", user.DisplayName)
		assert.Equal(t, signupID, user.WebAuthnUserID)
		assert.Equal(t, "ecdh", user.RequestEncEcdhPubkey)
		assert.Len(t, auditEvents(t, h, userID, db.AuditAuthFinalizeSignup), 1)

		creds, err := h.db.AuthStore().ListCredentials(t.Context(), userID)
		require.NoError(t, err)
		require.Len(t, creds, 1)
		assert.Equal(t, "cred-1", creds[0].CredentialID)
		assert.EqualValues(t, 5, creds[0].SignCount)
		assert.Equal(t, "wrapped-key", creds[0].WrappedPrimaryKey)

		// The signup is gone
		got, err = signup.Get(t.Context())
		require.NoError(t, err)
		assert.Nil(t, got)

		_, err = signup.Finalize(t.Context(), db.FinalizeSignupInput{}, nil)
		require.ErrorIs(t, err, ErrSignupNotFound)
	})

	t.Run("finalize requires a registered passkey", func(t *testing.T) {
		signup := h.Signup("signup-begun")
		err := signup.Begin(t.Context(), Signup{
			UserID:         "user-signup-begun",
			WebAuthnUserID: "signup-begun",
			ExpiresAt:      time.Now().Add(time.Minute),
		})
		require.NoError(t, err)

		_, err = signup.Finalize(t.Context(), db.FinalizeSignupInput{}, nil)
		require.ErrorIs(t, err, ErrSignupNotFound)
	})

	t.Run("finalize reports a user that exists already", func(t *testing.T) {
		const userID = "user-signup-exists"

		// Create the user in the database first
		_, err := db.ExecuteInTransaction(t.Context(), h.db, 30*time.Second, func(ctx context.Context, tx *db.DbTx) (struct{}, error) {
			_, rErr := tx.AuthStore().RegisterUser(ctx, db.RegisterUserInput{
				UserID:         userID,
				WebAuthnUserID: "webauthn-" + userID,
				CredentialID:   "cred-" + userID,
				PublicKey:      `{}`,
			})
			return struct{}{}, rErr
		})
		require.NoError(t, err)

		signup := registerTestSignup(t, h, "signup-exists", userID)
		_, err = signup.Finalize(t.Context(), db.FinalizeSignupInput{}, nil)
		require.ErrorIs(t, err, ErrSignupAlreadyFinalized)
	})

	t.Run("expired signup", func(t *testing.T) {
		signup := h.Signup("signup-expired")
		err := signup.Begin(t.Context(), Signup{
			UserID:         "user-signup-expired",
			WebAuthnUserID: "signup-expired",
			ExpiresAt:      time.Now().Add(-time.Second),
		})
		require.NoError(t, err)

		got, err := signup.Get(t.Context())
		require.NoError(t, err)
		assert.Nil(t, got)

		_, err = signup.Register(t.Context(), SignupCredential{ID: "cred-1", PublicKey: `{}`}, nil)
		require.ErrorIs(t, err, ErrSignupNotFound)
	})

	t.Run("invalid IDs", func(t *testing.T) {
		for _, signupID := range []string{"", "a/b", strings.Repeat("a", maxSignupIDLength+1)} {
			signup := h.Signup(signupID)

			err := signup.Begin(t.Context(), Signup{UserID: "user", ExpiresAt: time.Now().Add(time.Minute)})
			require.Error(t, err)

			got, err := signup.Get(t.Context())
			require.NoError(t, err)
			assert.Nil(t, got)

			_, err = signup.Register(t.Context(), SignupCredential{ID: "cred-1"}, nil)
			require.ErrorIs(t, err, ErrSignupNotFound)
		}
	})
}

func TestSignupActorCleanup(t *testing.T) {
	h := newTestHost(t, newTestDB(t), ":memory:")

	err := h.Signup("signup-cleanup").Begin(t.Context(), Signup{
		UserID:         "user-signup-cleanup",
		WebAuthnUserID: "signup-cleanup",
		ExpiresAt:      time.Now().Add(time.Second),
	})
	require.NoError(t, err)
	require.Equal(t, 1, countActorStates(t, h, actorTypeSignup))

	// The cleanup alarm deletes the signup once it expires
	require.Eventually(t, func() bool {
		return countActorStates(t, h, actorTypeSignup) == 0
	}, 15*time.Second, 100*time.Millisecond, "the expired signup was not deleted")
}

// registerTestSignup creates a signup with a registered passkey
func registerTestSignup(t *testing.T, h *Host, signupID string, userID string) SignupClient {
	t.Helper()

	signup := h.Signup(signupID)
	err := signup.Begin(t.Context(), Signup{
		UserID:         userID,
		WebAuthnUserID: signupID,
		ExpiresAt:      time.Now().Add(time.Minute),
	})
	require.NoError(t, err)

	_, err = signup.Register(t.Context(), SignupCredential{ID: "cred-" + signupID, PublicKey: `{}`, SignCount: 1}, nil)
	require.NoError(t, err)

	return signup
}

// signupTestAudit returns an audit event where the user is the actor
func signupTestAudit(eventType db.EventType, userID string) *db.AuditEventInput {
	return &db.AuditEventInput{
		EventType:   eventType,
		Outcome:     db.AuditOutcomeSuccess,
		AuthMethod:  db.AuditAuthMethodSession,
		ActorUserID: &userID,
	}
}
