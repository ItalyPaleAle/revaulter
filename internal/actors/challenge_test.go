package actors

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestChallengeActorID(t *testing.T) {
	t.Run("login challenges are keyed by their ID", func(t *testing.T) {
		id, err := challengeActorID(ChallengeKindLogin, "abc", "")
		require.NoError(t, err)
		assert.Equal(t, "login:abc", id)
	})

	t.Run("device login challenges are keyed by their ID", func(t *testing.T) {
		id, err := challengeActorID(ChallengeKindDeviceLogin, "abc", "")
		require.NoError(t, err)
		assert.Equal(t, "device-login:abc", id)

		_, err = challengeActorID(ChallengeKindDeviceLogin, "a/b", "")
		require.ErrorIs(t, err, ErrInvalidChallenge)
	})

	t.Run("add-credential challenges are keyed by the user", func(t *testing.T) {
		id, err := challengeActorID(ChallengeKindAddCredential, "abc", "user-1")
		require.NoError(t, err)
		assert.Equal(t, "add-credential:user-1", id)
	})

	t.Run("invalid login challenge IDs", func(t *testing.T) {
		for _, challengeID := range []string{"", "a/b", strings.Repeat("a", maxChallengeIDLength+1)} {
			_, err := challengeActorID(ChallengeKindLogin, challengeID, "")
			require.ErrorIs(t, err, ErrInvalidChallenge)
		}
	})

	t.Run("add-credential challenges require a user", func(t *testing.T) {
		_, err := challengeActorID(ChallengeKindAddCredential, "abc", "")
		require.Error(t, err)
	})

	t.Run("unknown kind", func(t *testing.T) {
		_, err := challengeActorID(ChallengeKind("other"), "abc", "user-1")
		require.Error(t, err)
	})
}

func TestChallengeActor(t *testing.T) {
	h := newTestHost(t, newTestDB(t), ":memory:")

	t.Run("login challenge is consumed once", func(t *testing.T) {
		challengeID, err := h.BeginChallenge(t.Context(), ChallengeKindLogin, "", time.Now().Add(time.Minute), []byte(`{"challenge":"c1"}`))
		require.NoError(t, err)
		require.NotEmpty(t, challengeID)

		payload, err := h.ConsumeChallenge(t.Context(), ChallengeKindLogin, challengeID, "")
		require.NoError(t, err)
		assert.JSONEq(t, `{"challenge":"c1"}`, string(payload))

		_, err = h.ConsumeChallenge(t.Context(), ChallengeKindLogin, challengeID, "")
		require.ErrorIs(t, err, ErrInvalidChallenge)
	})

	t.Run("device login challenge can't be used for a passkey sign-in", func(t *testing.T) {
		challengeID, err := h.BeginChallenge(t.Context(), ChallengeKindDeviceLogin, "", time.Now().Add(time.Minute), []byte(`{"challenge":"d1"}`))
		require.NoError(t, err)

		_, err = h.ConsumeChallenge(t.Context(), ChallengeKindLogin, challengeID, "")
		require.ErrorIs(t, err, ErrInvalidChallenge)

		payload, err := h.ConsumeChallenge(t.Context(), ChallengeKindDeviceLogin, challengeID, "")
		require.NoError(t, err)
		assert.JSONEq(t, `{"challenge":"d1"}`, string(payload))
	})

	t.Run("unknown and invalid challenges", func(t *testing.T) {
		_, err := h.ConsumeChallenge(t.Context(), ChallengeKindLogin, "does-not-exist", "")
		require.ErrorIs(t, err, ErrInvalidChallenge)

		_, err = h.ConsumeChallenge(t.Context(), ChallengeKindLogin, "", "")
		require.ErrorIs(t, err, ErrInvalidChallenge)

		_, err = h.ConsumeChallenge(t.Context(), ChallengeKindLogin, "a/b", "")
		require.ErrorIs(t, err, ErrInvalidChallenge)
	})

	t.Run("expired challenge", func(t *testing.T) {
		challengeID, err := h.BeginChallenge(t.Context(), ChallengeKindLogin, "", time.Now().Add(-time.Second), []byte(`{}`))
		require.NoError(t, err)

		_, err = h.ConsumeChallenge(t.Context(), ChallengeKindLogin, challengeID, "")
		require.ErrorIs(t, err, ErrInvalidChallenge)
	})

	t.Run("add-credential challenge is bound to the user", func(t *testing.T) {
		const userID = "user-add-credential"

		pending, err := h.HasPendingAddCredentialChallenge(t.Context(), userID)
		require.NoError(t, err)
		assert.False(t, pending)

		challengeID, err := h.BeginChallenge(t.Context(), ChallengeKindAddCredential, userID, time.Now().Add(time.Minute), []byte(`{"n":1}`))
		require.NoError(t, err)

		pending, err = h.HasPendingAddCredentialChallenge(t.Context(), userID)
		require.NoError(t, err)
		assert.True(t, pending)

		// Another user can't consume it, and that doesn't use it up
		_, err = h.ConsumeChallenge(t.Context(), ChallengeKindAddCredential, challengeID, "user-other")
		require.ErrorIs(t, err, ErrInvalidChallenge)

		// Nor can the ID be used for a sign-in
		_, err = h.ConsumeChallenge(t.Context(), ChallengeKindLogin, challengeID, "")
		require.ErrorIs(t, err, ErrInvalidChallenge)

		payload, err := h.ConsumeChallenge(t.Context(), ChallengeKindAddCredential, challengeID, userID)
		require.NoError(t, err)
		assert.JSONEq(t, `{"n":1}`, string(payload))

		pending, err = h.HasPendingAddCredentialChallenge(t.Context(), userID)
		require.NoError(t, err)
		assert.False(t, pending)
	})

	t.Run("a new add-credential challenge replaces the previous one", func(t *testing.T) {
		const userID = "user-add-credential-replace"

		first, err := h.BeginChallenge(t.Context(), ChallengeKindAddCredential, userID, time.Now().Add(time.Minute), []byte(`{"n":1}`))
		require.NoError(t, err)
		second, err := h.BeginChallenge(t.Context(), ChallengeKindAddCredential, userID, time.Now().Add(time.Minute), []byte(`{"n":2}`))
		require.NoError(t, err)

		_, err = h.ConsumeChallenge(t.Context(), ChallengeKindAddCredential, first, userID)
		require.ErrorIs(t, err, ErrInvalidChallenge)

		payload, err := h.ConsumeChallenge(t.Context(), ChallengeKindAddCredential, second, userID)
		require.NoError(t, err)
		assert.JSONEq(t, `{"n":2}`, string(payload))
	})

	t.Run("expired add-credential challenge isn't pending", func(t *testing.T) {
		const userID = "user-add-credential-expired"

		_, err := h.BeginChallenge(t.Context(), ChallengeKindAddCredential, userID, time.Now().Add(-time.Second), nil)
		require.NoError(t, err)

		pending, err := h.HasPendingAddCredentialChallenge(t.Context(), userID)
		require.NoError(t, err)
		assert.False(t, pending)
	})
}

func TestChallengeActorCleanup(t *testing.T) {
	h := newTestHost(t, newTestDB(t), ":memory:")

	_, err := h.BeginChallenge(t.Context(), ChallengeKindLogin, "", time.Now().Add(time.Second), []byte(`{}`))
	require.NoError(t, err)
	require.Equal(t, 1, countActorStates(t, h, actorTypeChallenge))

	// The cleanup alarm deletes the challenge once it expires
	require.Eventually(t, func() bool {
		return countActorStates(t, h, actorTypeChallenge) == 0
	}, 15*time.Second, 100*time.Millisecond, "the expired challenge was not deleted")
}

// countActorStates returns how many actors of a type have state
func countActorStates(t *testing.T, h *Host, actorType string) int {
	t.Helper()

	list, err := h.host.Service().ListStates(t.Context(), actorType, nil)
	require.NoError(t, err)

	return len(list.States)
}
