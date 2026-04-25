package db

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestAuthStoreRegisterUserAndLogin(t *testing.T) {
	conn := newTestDatabase(t)

	require.NoError(t, RunMigrations(t.Context(), conn, nil))

	_, _ = ExecuteInTransaction(t.Context(), conn, 30*time.Second, func(ctx context.Context, tx *DbTx) (any, error) {
		as := tx.AuthStore()

		n, err := as.CountUsers(ctx)
		require.NoError(t, err)
		require.Equal(t, 0, n)

		ch, err := as.BeginChallenge(ctx, "register", "user-1", createChallenge(t), time.Now().Add(time.Minute), nil)
		require.NoError(t, err)
		require.NotEmpty(t, ch.Challenge)

		err = as.ConsumeChallenge(ctx, ch.ID, "register", "", nil)
		require.NoError(t, err)

		sess, err := as.RegisterUser(ctx, RegisterUserInput{
			UserID:         "user-1",
			DisplayName:    "Alice",
			WebAuthnUserID: "webauthn-user-1",
			CredentialID:   "cred-1",
			PublicKey:      `{"kty":"EC"}`,
			SignCount:      1,
			SessionTTL:     time.Minute,
		})
		require.NoError(t, err)
		require.NotNil(t, sess)
		require.Equal(t, "user-1", sess.ID)
		require.Equal(t, "Alice", sess.DisplayName)
		require.Len(t, sess.RequestKey, 20)
		require.Empty(t, sess.AllowedIPs)

		gotUser, err := as.GetUserByRequestKey(ctx, sess.RequestKey)
		require.NoError(t, err)
		require.NotNil(t, gotUser)
		require.Equal(t, "user-1", gotUser.ID)

		loginCh, err := as.BeginChallenge(ctx, "login", "", createChallenge(t), time.Now().Add(time.Minute), nil)
		require.NoError(t, err)
		err = as.ConsumeChallenge(ctx, loginCh.ID, "login", "", nil)
		require.NoError(t, err)

		err = as.Login(ctx, LoginInput{
			UserID:       "user-1",
			CredentialID: "cred-1",
			SignCount:    2,
			SessionTTL:   time.Minute,
		})
		require.NoError(t, err)

		loginSess, err := as.GetUserByID(ctx, "user-1")
		require.NoError(t, err)
		require.NotNil(t, loginSess)
		require.Equal(t, sess.RequestKey, loginSess.RequestKey)

		creds, err := as.ListCredentials(ctx, "user-1")
		require.NoError(t, err)
		require.Len(t, creds, 1)
		require.EqualValues(t, 2, creds[0].SignCount)

		return nil, nil
	})
}

func createChallenge(t *testing.T) string {
	t.Helper()

	rawChallenge := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, rawChallenge)
	require.NoError(t, err)

	return base64.RawURLEncoding.EncodeToString(rawChallenge)
}

func TestAuthStorePasswordCanaryAndAllowedIPs(t *testing.T) {
	conn := newTestDatabase(t)

	require.NoError(t, RunMigrations(t.Context(), conn, nil))

	_, _ = ExecuteInTransaction(t.Context(), conn, 30*time.Second, func(ctx context.Context, tx *DbTx) (any, error) {
		as := tx.AuthStore()

		_, err := as.RegisterUser(ctx, RegisterUserInput{
			UserID:         "user-1",
			DisplayName:    "",
			WebAuthnUserID: "webauthn-user-1",
			CredentialID:   "cred-1",
			PublicKey:      `{"kty":"EC"}`,
			SignCount:      1,
			SessionTTL:     time.Minute,
		})
		require.NoError(t, err)

		_, err = as.FinalizeSignup(ctx, FinalizeSignupInput{
			UserID:                "user-1",
			WrappedPrimaryKey:     "canary-1",
			RequestEncEcdhPubkey:  `{"kty":"EC","crv":"P-256","x":"test","y":"test"}`,
			RequestEncMlkemPubkey: "dGVzdC1tbGtlbS1wdWJrZXk",
		})
		require.NoError(t, err)

		_, err = as.FinalizeSignup(ctx, FinalizeSignupInput{
			UserID:                "user-1",
			WrappedPrimaryKey:     "canary-2",
			RequestEncEcdhPubkey:  `{"kty":"EC"}`,
			RequestEncMlkemPubkey: "dGVzdA",
		})
		require.ErrorIs(t, err, ErrAlreadyFinalized)

		allowed, err := as.UpdateAllowedIPs(ctx, "user-1", []string{"127.0.0.1", " 10.0.0.0/8 ", "::1", "127.0.0.1"})
		require.NoError(t, err)
		require.Equal(t, []string{"127.0.0.1", "10.0.0.0/8", "::1"}, allowed)

		user, err := as.GetUserByID(ctx, "user-1")
		require.NoError(t, err)
		require.Equal(t, []string{"127.0.0.1", "10.0.0.0/8", "::1"}, user.AllowedIPs)

		allowed, err = as.UpdateAllowedIPs(ctx, "user-1", []string{})
		require.NoError(t, err)
		require.Empty(t, allowed)

		return nil, nil
	})
}

func TestAuthStoreRegenerateRequestKey(t *testing.T) {
	conn := newTestDatabase(t)

	require.NoError(t, RunMigrations(t.Context(), conn, nil))

	_, _ = ExecuteInTransaction(t.Context(), conn, 30*time.Second, func(ctx context.Context, tx *DbTx) (any, error) {
		as := tx.AuthStore()

		sess, err := as.RegisterUser(ctx, RegisterUserInput{
			UserID:         "user-1",
			DisplayName:    "Alice",
			WebAuthnUserID: "webauthn-user-1",
			CredentialID:   "cred-1",
			PublicKey:      `{"kty":"EC"}`,
			SignCount:      1,
			SessionTTL:     time.Minute,
		})
		require.NoError(t, err)

		// RegenerateRequestKey requires the account to be active and ready;
		// finalize the signup first.
		_, err = as.FinalizeSignup(ctx, FinalizeSignupInput{
			UserID:                "user-1",
			RequestEncEcdhPubkey:  `{"kty":"EC"}`,
			RequestEncMlkemPubkey: "mlkem-pub",
		})
		require.NoError(t, err)

		newKey, err := as.RegenerateRequestKey(ctx, "user-1")
		require.NoError(t, err)
		require.Len(t, newKey, 20)
		require.NotEqual(t, sess.RequestKey, newKey)

		user, err := as.GetUserByRequestKey(ctx, newKey)
		require.NoError(t, err)
		require.NotNil(t, user)
		require.Equal(t, "user-1", user.ID)

		oldUser, err := as.GetUserByRequestKey(ctx, sess.RequestKey)
		require.NoError(t, err)
		require.Nil(t, oldUser)

		return nil, nil
	})
}

func TestParseAllowedIPsCSV(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{name: "empty string", input: "", expected: nil},
		{name: "whitespace only", input: "  \t  ", expected: nil},
		{name: "single value", input: "127.0.0.1", expected: []string{"127.0.0.1"}},
		{name: "trims and drops empty entries", input: " 127.0.0.1 , , 10.0.0.0/8,   ::1  ", expected: []string{"127.0.0.1", "10.0.0.0/8", "::1"}},
		{name: "all empty entries", input: ", , ,", expected: nil},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := parseAllowedIPsCSV(test.input)
			require.Equal(t, test.expected, result)
		})
	}
}

func TestNormalizeAllowedIPsEmptyInputs(t *testing.T) {
	tests := []struct {
		name  string
		input []string
	}{
		{name: "nil input", input: nil},
		{name: "blank entries only", input: []string{"", "  ", "\t", "\n"}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := NormalizeAllowedIPs(test.input)
			require.NoError(t, err)
			require.Empty(t, result)
		})
	}
}

func TestNormalizeAllowedIPsNormalizesCanonicalizesDeduplicatesAndPreservesOrder(t *testing.T) {
	result, err := NormalizeAllowedIPs([]string{
		" 127.0.0.1 ",
		"10.123.45.67/8",
		"2001:DB8::1",
		"2001:db8::abcd/64",
		"10.0.0.0/8",
		"2001:db8::1",
		"2001:db8::/64",
		"",
		"   ",
		"127.0.0.1",
	})
	require.NoError(t, err)
	require.Equal(t, []string{
		"127.0.0.1",
		"10.0.0.0/8",
		"2001:db8::1",
		"2001:db8::/64",
	}, result)
}

func TestNormalizeAllowedIPsInvalidIP(t *testing.T) {
	result, err := NormalizeAllowedIPs([]string{"127.0.0.1", "not-an-ip"})
	require.Nil(t, result)
	require.ErrorIs(t, err, ErrInvalidIP)
	require.EqualError(t, err, "invalid IP: not-an-ip")
}

func TestNormalizeAllowedIPsInvalidCIDR(t *testing.T) {
	result, err := NormalizeAllowedIPs([]string{" 10.0.0.0/33 "})
	require.Nil(t, result)
	require.ErrorIs(t, err, ErrInvalidCIDR)
	require.EqualError(t, err, "invalid CIDR: 10.0.0.0/33")
}

func TestAuthStoreDeleteExpiredAuthChallenge(t *testing.T) {
	conn := newTestDatabase(t)

	require.NoError(t, RunMigrations(t.Context(), conn, nil))

	_, _ = ExecuteInTransaction(t.Context(), conn, 30*time.Second, func(ctx context.Context, tx *DbTx) (any, error) {
		as := tx.AuthStore()

		now := time.Now().UTC().Truncate(time.Second)
		expiredChallenge, err := as.BeginChallenge(ctx, "login", "", "expired-challenge", now.Add(-11*time.Minute), nil)
		require.NoError(t, err)
		usedChallenge, err := as.BeginChallenge(ctx, "login", "", "used-challenge", now.Add(5*time.Minute), nil)
		require.NoError(t, err)
		freshChallenge, err := as.BeginChallenge(ctx, "login", "", "fresh-challenge", now.Add(5*time.Minute), nil)
		require.NoError(t, err)

		err = as.ConsumeChallenge(ctx, usedChallenge.ID, "login", "", nil)
		require.NoError(t, err)

		err = as.DeleteExpiredAuthChallenge(ctx, expiredChallenge.ID, now)
		require.NoError(t, err)
		err = as.DeleteExpiredAuthChallenge(ctx, usedChallenge.ID, now)
		require.NoError(t, err)
		err = as.DeleteExpiredAuthChallenge(ctx, freshChallenge.ID, now)
		require.NoError(t, err)

		err = as.ConsumeChallenge(ctx, expiredChallenge.ID, "login", "", nil)
		require.ErrorIs(t, err, ErrInvalidChallenge)

		err = as.ConsumeChallenge(ctx, usedChallenge.ID, "login", "", nil)
		require.ErrorIs(t, err, ErrInvalidChallenge)

		err = as.ConsumeChallenge(ctx, freshChallenge.ID, "login", "", nil)
		require.NoError(t, err)

		return nil, nil
	})
}

func TestAuthStoreConsumeChallengePayload(t *testing.T) {
	conn := newTestDatabase(t)

	require.NoError(t, RunMigrations(t.Context(), conn, nil))

	_, _ = ExecuteInTransaction(t.Context(), conn, 30*time.Second, func(ctx context.Context, tx *DbTx) (any, error) {
		as := tx.AuthStore()

		type challengePayload struct {
			UserID string `json:"userId"`
			Step   int    `json:"step"`
		}

		expected := challengePayload{
			UserID: "user-1",
			Step:   2,
		}
		challenge, err := as.BeginChallenge(ctx, "login", "user-1", "payload-challenge", time.Now().Add(time.Minute), expected)
		require.NoError(t, err)

		var got challengePayload
		err = as.ConsumeChallenge(ctx, challenge.ID, "login", "", &got)
		require.NoError(t, err)
		require.Equal(t, expected, got)

		err = as.ConsumeChallenge(ctx, challenge.ID, "login", "", nil)
		require.ErrorIs(t, err, ErrInvalidChallenge)

		challengeNoPayload, err := as.BeginChallenge(ctx, "register", "user-2", "no-payload-challenge", time.Now().Add(time.Minute), nil)
		require.NoError(t, err)

		got = challengePayload{}
		err = as.ConsumeChallenge(ctx, challengeNoPayload.ID, "register", "", &got)
		require.NoError(t, err)
		require.Equal(t, challengePayload{}, got)

		return nil, nil
	})
}

func TestAuthStoreConsumeChallengeUserBinding(t *testing.T) {
	conn := newTestDatabase(t)

	require.NoError(t, RunMigrations(t.Context(), conn, nil))

	_, _ = ExecuteInTransaction(t.Context(), conn, 30*time.Second, func(ctx context.Context, tx *DbTx) (any, error) {
		as := tx.AuthStore()

		// A challenge bound to user-1
		ch, err := as.BeginChallenge(ctx, "add-credential", "user-1", "user-bound-challenge", time.Now().Add(time.Minute), nil)
		require.NoError(t, err)

		// Consuming with the wrong userID must fail and must not mark the row as used
		err = as.ConsumeChallenge(ctx, ch.ID, "add-credential", "user-2", nil)
		require.ErrorIs(t, err, ErrInvalidChallenge)

		// The legitimate owner can still consume it
		err = as.ConsumeChallenge(ctx, ch.ID, "add-credential", "user-1", nil)
		require.NoError(t, err)

		// And only once — a second consume even by the rightful owner returns ErrInvalidChallenge
		err = as.ConsumeChallenge(ctx, ch.ID, "add-credential", "user-1", nil)
		require.ErrorIs(t, err, ErrInvalidChallenge)

		return nil, nil
	})
}

func TestAuthStoreHasPendingChallenge(t *testing.T) {
	conn := newTestDatabase(t)

	require.NoError(t, RunMigrations(t.Context(), conn, nil))

	_, _ = ExecuteInTransaction(t.Context(), conn, 30*time.Second, func(ctx context.Context, tx *DbTx) (any, error) {
		as := tx.AuthStore()

		now := time.Now().UTC().Truncate(time.Second)

		// Nothing in the table yet, so no pending challenge exists
		pending, err := as.HasPendingChallenge(ctx, "user-1", "add-credential")
		require.NoError(t, err)
		require.False(t, pending)

		// A fresh add-credential challenge for user-1 makes the check return true
		freshAdd, err := as.BeginChallenge(ctx, "add-credential", "user-1", "fresh-add", now.Add(5*time.Minute), nil)
		require.NoError(t, err)

		pending, err = as.HasPendingChallenge(ctx, "user-1", "add-credential")
		require.NoError(t, err)
		require.True(t, pending)

		// Challenges of a different kind do not count
		pending, err = as.HasPendingChallenge(ctx, "user-1", "login")
		require.NoError(t, err)
		require.False(t, pending)

		// Challenges belonging to a different user do not count
		pending, err = as.HasPendingChallenge(ctx, "user-other", "add-credential")
		require.NoError(t, err)
		require.False(t, pending)

		// Once consumed the challenge is no longer pending
		err = as.ConsumeChallenge(ctx, freshAdd.ID, "add-credential", "user-1", nil)
		require.NoError(t, err)

		pending, err = as.HasPendingChallenge(ctx, "user-1", "add-credential")
		require.NoError(t, err)
		require.False(t, pending)

		// An expired (but not consumed) challenge is also not pending
		_, err = as.BeginChallenge(ctx, "add-credential", "user-1", "expired-add", now.Add(-time.Minute), nil)
		require.NoError(t, err)

		pending, err = as.HasPendingChallenge(ctx, "user-1", "add-credential")
		require.NoError(t, err)
		require.False(t, pending)

		return nil, nil
	})
}

func TestAuthStoreDeleteNonreadyUser(t *testing.T) {
	conn := newTestDatabase(t)

	require.NoError(t, RunMigrations(t.Context(), conn, nil))

	_, _ = ExecuteInTransaction(t.Context(), conn, 30*time.Second, func(ctx context.Context, tx *DbTx) (any, error) {
		as := tx.AuthStore()

		// #nosec G101 -- Hardcoded credentials are test ones
		nonreadyOldSession, err := as.RegisterUser(ctx, RegisterUserInput{
			UserID:         "user-nonready-old",
			DisplayName:    "Old Nonready",
			WebAuthnUserID: "webauthn-user-nonready-old",
			CredentialID:   "cred-nonready-old",
			PublicKey:      `{"kty":"EC"}`,
			SignCount:      1,
			SessionTTL:     time.Hour,
		})
		require.NoError(t, err)

		// #nosec G101 -- Hardcoded credentials are test ones
		nonreadyFreshSession, err := as.RegisterUser(ctx, RegisterUserInput{
			UserID:         "user-nonready-fresh",
			DisplayName:    "Fresh Nonready",
			WebAuthnUserID: "webauthn-user-nonready-fresh",
			CredentialID:   "cred-nonready-fresh",
			PublicKey:      `{"kty":"EC"}`,
			SignCount:      1,
			SessionTTL:     time.Hour,
		})
		require.NoError(t, err)

		// #nosec G101 -- Hardcoded credentials are test ones
		readySession, err := as.RegisterUser(ctx, RegisterUserInput{
			UserID:         "user-ready",
			DisplayName:    "Ready User",
			WebAuthnUserID: "webauthn-user-ready",
			CredentialID:   "cred-ready",
			PublicKey:      `{"kty":"EC"}`,
			SignCount:      1,
			SessionTTL:     time.Hour,
		})
		require.NoError(t, err)

		_, err = tx.Exec(ctx, `UPDATE v2_users SET created_at = $2 WHERE id = $1`, nonreadyOldSession.ID, time.Now().Add(-25*time.Hour).Unix())
		require.NoError(t, err)

		_, err = tx.Exec(ctx, `UPDATE v2_users SET created_at = $2 WHERE id = $1`, nonreadyFreshSession.ID, time.Now().Add(-23*time.Hour).Unix())
		require.NoError(t, err)

		_, err = as.FinalizeSignup(ctx, FinalizeSignupInput{
			UserID:                readySession.ID,
			WrappedPrimaryKey:     "canary-ready",
			RequestEncEcdhPubkey:  `{"kty":"EC"}`,
			RequestEncMlkemPubkey: "mlkem-ready",
		})
		require.NoError(t, err)

		_, err = tx.Exec(ctx, `UPDATE v2_users SET created_at = $2 WHERE id = $1`, readySession.ID, time.Now().Add(-25*time.Hour).Unix())
		require.NoError(t, err)

		err = as.DeleteNonreadyUser(ctx, nonreadyOldSession.ID, time.Now().UTC())
		require.NoError(t, err)
		err = as.DeleteNonreadyUser(ctx, nonreadyFreshSession.ID, time.Now().UTC())
		require.NoError(t, err)
		err = as.DeleteNonreadyUser(ctx, readySession.ID, time.Now().UTC())
		require.NoError(t, err)

		user, err := as.GetUserByID(ctx, nonreadyOldSession.ID)
		require.NoError(t, err)
		require.Nil(t, user)

		user, err = as.GetUserByID(ctx, nonreadyFreshSession.ID)
		require.NoError(t, err)
		require.NotNil(t, user)
		require.False(t, user.Ready)

		user, err = as.GetUserByID(ctx, readySession.ID)
		require.NoError(t, err)
		require.NotNil(t, user)
		require.True(t, user.Ready)

		return nil, nil
	})
}

func TestAuthStoreUpdateDisplayName(t *testing.T) {
	conn := newTestDatabase(t)

	require.NoError(t, RunMigrations(t.Context(), conn, nil))

	_, _ = ExecuteInTransaction(t.Context(), conn, 30*time.Second, func(ctx context.Context, tx *DbTx) (any, error) {
		as := tx.AuthStore()

		_, err := as.RegisterUser(ctx, RegisterUserInput{
			UserID:         "user-1",
			DisplayName:    "Alice",
			WebAuthnUserID: "webauthn-user-1",
			CredentialID:   "cred-1",
			PublicKey:      `{"kty":"EC"}`,
			SignCount:      1,
			SessionTTL:     time.Minute,
		})
		require.NoError(t, err)

		_, err = as.FinalizeSignup(ctx, FinalizeSignupInput{
			UserID:                "user-1",
			RequestEncEcdhPubkey:  `{"kty":"EC"}`,
			RequestEncMlkemPubkey: "mlkem-pub",
		})
		require.NoError(t, err)

		// Successful update
		err = as.UpdateDisplayName(ctx, "user-1", "Bob")
		require.NoError(t, err)
		user, err := as.GetUserByID(ctx, "user-1")
		require.NoError(t, err)
		require.Equal(t, "Bob", user.DisplayName)

		// Empty display name is valid
		err = as.UpdateDisplayName(ctx, "user-1", "")
		require.NoError(t, err)
		user, err = as.GetUserByID(ctx, "user-1")
		require.NoError(t, err)
		require.Empty(t, user.DisplayName)

		// Too-long display name
		err = as.UpdateDisplayName(ctx, "user-1", strings.Repeat("a", 101))
		require.ErrorIs(t, err, ErrDisplayNameTooLong)

		// Non-existent user
		err = as.UpdateDisplayName(ctx, "no-such-user", "Test")
		require.ErrorIs(t, err, ErrUserNotFound)

		return nil, nil
	})
}

func TestAuthStoreUpdateCredentialWrappedKey(t *testing.T) {
	conn := newTestDatabase(t)

	require.NoError(t, RunMigrations(t.Context(), conn, nil))

	_, _ = ExecuteInTransaction(t.Context(), conn, 30*time.Second, func(ctx context.Context, tx *DbTx) (any, error) {
		as := tx.AuthStore()

		_, err := as.RegisterUser(ctx, RegisterUserInput{
			UserID:         "user-1",
			DisplayName:    "Alice",
			WebAuthnUserID: "webauthn-user-1",
			CredentialID:   "cred-1",
			PublicKey:      `{"kty":"EC"}`,
			SignCount:      1,
			SessionTTL:     time.Minute,
		})
		require.NoError(t, err)

		_, err = as.FinalizeSignup(ctx, FinalizeSignupInput{
			UserID:                "user-1",
			WrappedPrimaryKey:     "initial-key",
			RequestEncEcdhPubkey:  `{"kty":"EC"}`,
			RequestEncMlkemPubkey: "mlkem-pub",
		})
		require.NoError(t, err)

		// The initial wrapped primary key was set on the single credential via FinalizeSignup
		rec, err := as.GetCredentialByCredentialID(ctx, "cred-1", "user-1")
		require.NoError(t, err)
		require.NotNil(t, rec)
		require.Equal(t, "initial-key", rec.WrappedPrimaryKey)

		// Successful update
		err = as.UpdateCredentialWrappedKey(ctx, "cred-1", "user-1", "new-wrapped-key", "new-anchor-key")
		require.NoError(t, err)
		rec, err = as.GetCredentialByCredentialID(ctx, "cred-1", "user-1")
		require.NoError(t, err)
		require.Equal(t, "new-wrapped-key", rec.WrappedPrimaryKey)
		require.Equal(t, "new-anchor-key", rec.WrappedAnchorKey)

		// Empty string is valid (removes password)
		err = as.UpdateCredentialWrappedKey(ctx, "cred-1", "user-1", "", "")
		require.NoError(t, err)
		rec, err = as.GetCredentialByCredentialID(ctx, "cred-1", "user-1")
		require.NoError(t, err)
		require.Empty(t, rec.WrappedPrimaryKey)

		// Oversized value
		err = as.UpdateCredentialWrappedKey(ctx, "cred-1", "user-1", strings.Repeat("x", 513), "anchor")
		require.Error(t, err)
		require.Contains(t, err.Error(), "too large")

		// Non-existent credential
		err = as.UpdateCredentialWrappedKey(ctx, "no-such-cred", "user-1", "key", "anchor")
		require.ErrorIs(t, err, ErrCredentialNotFound)

		// Credential belonging to a different user
		err = as.UpdateCredentialWrappedKey(ctx, "cred-1", "other-user", "key", "anchor")
		require.ErrorIs(t, err, ErrCredentialNotFound)

		return nil, nil
	})
}

func TestAuthStoreCredentialWrappedKeyEpochRotation(t *testing.T) {
	conn := newTestDatabase(t)

	require.NoError(t, RunMigrations(t.Context(), conn, nil))

	_, _ = ExecuteInTransaction(t.Context(), conn, 30*time.Second, func(ctx context.Context, tx *DbTx) (any, error) {
		as := tx.AuthStore()

		_, err := as.RegisterUser(ctx, RegisterUserInput{
			UserID:         "user-1",
			DisplayName:    "Alice",
			WebAuthnUserID: "webauthn-user-1",
			CredentialID:   "cred-1",
			PublicKey:      `{"kty":"EC"}`,
			SignCount:      1,
			SessionTTL:     time.Minute,
		})
		require.NoError(t, err)

		_, err = as.FinalizeSignup(ctx, FinalizeSignupInput{
			UserID:                "user-1",
			WrappedPrimaryKey:     "wrapped-1-v1",
			RequestEncEcdhPubkey:  `{"kty":"EC"}`,
			RequestEncMlkemPubkey: "mlkem-pub",
		})
		require.NoError(t, err)

		err = as.AddCredential(ctx, AddCredentialInput{
			UserID:            "user-1",
			CredentialID:      "cred-2",
			DisplayName:       "Second",
			PublicKey:         `{"kty":"EC"}`,
			SignCount:         1,
			WrappedPrimaryKey: "wrapped-2-v1",
		})
		require.NoError(t, err)

		rec1, err := as.GetCredentialByCredentialID(ctx, "cred-1", "user-1")
		require.NoError(t, err)
		rec2, err := as.GetCredentialByCredentialID(ctx, "cred-2", "user-1")
		require.NoError(t, err)
		require.EqualValues(t, 1, rec1.WrappedKeyEpoch)
		require.EqualValues(t, 1, rec2.WrappedKeyEpoch)

		newEpoch, err := as.AdvanceWrappedKeyEpoch(ctx, "user-1")
		require.NoError(t, err)
		require.EqualValues(t, 2, newEpoch)

		err = as.UpdateCredentialWrappedKey(ctx, "cred-1", "user-1", "wrapped-1-v2", "anchor-1-v2")
		require.NoError(t, err)

		rec1, err = as.GetCredentialByCredentialID(ctx, "cred-1", "user-1")
		require.NoError(t, err)
		rec2, err = as.GetCredentialByCredentialID(ctx, "cred-2", "user-1")
		require.NoError(t, err)
		require.Equal(t, "wrapped-1-v2", rec1.WrappedPrimaryKey)
		require.Equal(t, "wrapped-2-v1", rec2.WrappedPrimaryKey)
		require.EqualValues(t, 2, rec1.WrappedKeyEpoch)
		require.EqualValues(t, 1, rec2.WrappedKeyEpoch)

		err = as.UpdateCredentialWrappedKey(ctx, "cred-2", "user-1", "wrapped-2-v2", "anchor-2-v2")
		require.NoError(t, err)

		rec2, err = as.GetCredentialByCredentialID(ctx, "cred-2", "user-1")
		require.NoError(t, err)
		require.Equal(t, "wrapped-2-v2", rec2.WrappedPrimaryKey)
		require.EqualValues(t, 2, rec2.WrappedKeyEpoch)

		return nil, nil
	})
}

func TestAuthStoreCredentialCRUD(t *testing.T) {
	conn := newTestDatabase(t)

	require.NoError(t, RunMigrations(t.Context(), conn, nil))

	_, _ = ExecuteInTransaction(t.Context(), conn, 30*time.Second, func(ctx context.Context, tx *DbTx) (any, error) {
		as := tx.AuthStore()

		_, err := as.RegisterUser(ctx, RegisterUserInput{
			UserID:                "user-1",
			DisplayName:           "Alice",
			WebAuthnUserID:        "webauthn-user-1",
			CredentialID:          "cred-1",
			CredentialDisplayName: "My Laptop",
			PublicKey:             `{"kty":"EC"}`,
			SignCount:             1,
			SessionTTL:            time.Minute,
		})
		require.NoError(t, err)

		// List — should have 1 credential with display name and timestamps
		creds, err := as.ListCredentials(ctx, "user-1")
		require.NoError(t, err)
		require.Len(t, creds, 1)
		require.NotEmpty(t, creds[0].ID)
		require.Equal(t, "cred-1", creds[0].CredentialID)
		require.Equal(t, "My Laptop", creds[0].DisplayName)
		require.NotZero(t, creds[0].CreatedAt)
		require.NotZero(t, creds[0].LastUsedAt)

		firstCredID := creds[0].ID

		// Add a second credential
		err = as.AddCredential(ctx, AddCredentialInput{
			UserID:       "user-1",
			CredentialID: "cred-2",
			DisplayName:  "My Phone",
			PublicKey:    `{"kty":"EC","crv":"P-256"}`,
			SignCount:    0,
		})
		require.NoError(t, err)

		creds, err = as.ListCredentials(ctx, "user-1")
		require.NoError(t, err)
		require.Len(t, creds, 2)

		secondCredID := creds[1].ID
		require.Equal(t, "My Phone", creds[1].DisplayName)

		// Rename second credential
		err = as.RenameCredential(ctx, secondCredID, "user-1", "Work Phone")
		require.NoError(t, err)
		creds, err = as.ListCredentials(ctx, "user-1")
		require.NoError(t, err)
		require.Equal(t, "Work Phone", creds[1].DisplayName)

		// Rename with too-long name
		err = as.RenameCredential(ctx, secondCredID, "user-1", strings.Repeat("a", 101))
		require.ErrorIs(t, err, ErrDisplayNameTooLong)

		// Rename nonexistent credential
		err = as.RenameCredential(ctx, "nonexistent-id", "user-1", "test")
		require.ErrorIs(t, err, ErrCredentialNotFound)

		// Rename credential belonging to different user
		err = as.RenameCredential(ctx, secondCredID, "other-user", "test")
		require.ErrorIs(t, err, ErrCredentialNotFound)

		// Delete second credential — should succeed
		err = as.DeleteCredential(ctx, secondCredID, "user-1")
		require.NoError(t, err)
		creds, err = as.ListCredentials(ctx, "user-1")
		require.NoError(t, err)
		require.Len(t, creds, 1)
		require.Equal(t, firstCredID, creds[0].ID)

		// Delete last credential — should fail
		err = as.DeleteCredential(ctx, firstCredID, "user-1")
		require.ErrorIs(t, err, ErrLastCredential)

		// Delete nonexistent credential
		err = as.DeleteCredential(ctx, "nonexistent-id", "user-1")
		require.ErrorIs(t, err, ErrCredentialNotFound)

		return nil, nil
	})
}
