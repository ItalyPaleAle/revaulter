package db

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestAuthStoreRegisterUserAndLogin(t *testing.T) {
	ctx := t.Context()
	conn := newTestDatabase(t)

	require.NoError(t, RunMigrations(ctx, conn, nil))

	store, err := NewAuthStore(conn, nil)
	require.NoError(t, err)

	n, err := store.CountUsers(ctx)
	require.NoError(t, err)
	require.Equal(t, 0, n)

	ch, err := store.BeginChallenge(ctx, "register", "user-1", time.Minute)
	require.NoError(t, err)
	require.NotEmpty(t, ch.Challenge)

	ok, err := store.ConsumeChallenge(ctx, ch.ID, "register")
	require.NoError(t, err)
	require.True(t, ok)

	sess, err := store.RegisterUser(ctx, RegisterUserInput{
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
	require.Equal(t, "user-1", sess.UserID)
	require.Equal(t, "Alice", sess.DisplayName)
	require.Len(t, sess.RequestKey, 20)
	require.Empty(t, sess.AllowedIPs)

	gotUser, err := store.GetUserByRequestKey(ctx, sess.RequestKey)
	require.NoError(t, err)
	require.NotNil(t, gotUser)
	require.Equal(t, "user-1", gotUser.ID)

	loginCh, err := store.BeginChallenge(ctx, "login", "", time.Minute)
	require.NoError(t, err)
	ok, err = store.ConsumeChallenge(ctx, loginCh.ID, "login")
	require.NoError(t, err)
	require.True(t, ok)

	loginSess, err := store.Login(ctx, LoginInput{
		UserID:       "user-1",
		CredentialID: "cred-1",
		SignCount:    2,
		SessionTTL:   time.Minute,
	})
	require.NoError(t, err)
	require.NotNil(t, loginSess)
	require.NotEqual(t, sess.ID, loginSess.ID)
	require.Equal(t, sess.RequestKey, loginSess.RequestKey)

	creds, err := store.ListCredentials(ctx, "user-1")
	require.NoError(t, err)
	require.Len(t, creds, 1)
	require.EqualValues(t, 2, creds[0].SignCount)

	got, err := store.GetSession(ctx, loginSess.ID)
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Equal(t, "user-1", got.UserID)
	require.Equal(t, "Alice", got.DisplayName)

	require.NoError(t, store.RevokeSession(ctx, loginSess.ID))
	got, err = store.GetSession(ctx, loginSess.ID)
	require.NoError(t, err)
	require.Nil(t, got)
}

func TestAuthStorePasswordCanaryAndAllowedIPs(t *testing.T) {
	ctx := t.Context()
	conn := newTestDatabase(t)

	require.NoError(t, RunMigrations(ctx, conn, nil))

	store, err := NewAuthStore(conn, nil)
	require.NoError(t, err)

	_, err = store.RegisterUser(ctx, RegisterUserInput{
		UserID:         "user-1",
		DisplayName:    "",
		WebAuthnUserID: "webauthn-user-1",
		CredentialID:   "cred-1",
		PublicKey:      `{"kty":"EC"}`,
		SignCount:      1,
		SessionTTL:     time.Minute,
	})
	require.NoError(t, err)

	require.NoError(t, store.FinalizeSignup(ctx, "user-1", "canary-1", `{"kty":"EC","crv":"P-256","x":"test","y":"test"}`, "dGVzdC1tbGtlbS1wdWJrZXk"))
	require.ErrorIs(t, store.FinalizeSignup(ctx, "user-1", "canary-2", `{"kty":"EC"}`, "dGVzdA"), ErrAlreadyFinalized)

	allowed, err := store.UpdateAllowedIPs(ctx, "user-1", []string{"127.0.0.1", " 10.0.0.0/8 ", "::1", "127.0.0.1"})
	require.NoError(t, err)
	require.Equal(t, []string{"127.0.0.1", "10.0.0.0/8", "::1"}, allowed)

	user, err := store.GetUserByID(ctx, "user-1")
	require.NoError(t, err)
	require.Equal(t, []string{"127.0.0.1", "10.0.0.0/8", "::1"}, user.AllowedIPs)

	allowed, err = store.UpdateAllowedIPs(ctx, "user-1", []string{})
	require.NoError(t, err)
	require.Empty(t, allowed)
}

func TestAuthStoreRegenerateRequestKey(t *testing.T) {
	ctx := t.Context()
	conn := newTestDatabase(t)

	require.NoError(t, RunMigrations(ctx, conn, nil))

	store, err := NewAuthStore(conn, nil)
	require.NoError(t, err)

	sess, err := store.RegisterUser(ctx, RegisterUserInput{
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
	require.NoError(t, store.FinalizeSignup(ctx, "user-1", "", `{"kty":"EC"}`, "mlkem-pub"))

	newKey, err := store.RegenerateRequestKey(ctx, "user-1")
	require.NoError(t, err)
	require.Len(t, newKey, 20)
	require.NotEqual(t, sess.RequestKey, newKey)

	user, err := store.GetUserByRequestKey(ctx, newKey)
	require.NoError(t, err)
	require.NotNil(t, user)
	require.Equal(t, "user-1", user.ID)

	oldUser, err := store.GetUserByRequestKey(ctx, sess.RequestKey)
	require.NoError(t, err)
	require.Nil(t, oldUser)
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
		{name: "all empty entries", input: ", , ,", expected: []string{}},
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
	require.EqualError(t, err, "invalid IP: not-an-ip")
}

func TestNormalizeAllowedIPsInvalidCIDR(t *testing.T) {
	result, err := NormalizeAllowedIPs([]string{" 10.0.0.0/33 "})
	require.Nil(t, result)
	require.EqualError(t, err, "invalid CIDR: 10.0.0.0/33")
}

func TestAuthStoreDeleteExpiredAuthChallenge(t *testing.T) {
	ctx := t.Context()
	conn := newTestDatabase(t)

	require.NoError(t, RunMigrations(ctx, conn, nil))

	store, err := NewAuthStore(conn, nil)
	require.NoError(t, err)

	now := time.Now().UTC().Truncate(time.Second)
	expiredChallenge, err := store.BeginChallengeWithPayload(ctx, "login", "", "expired-challenge", now.Add(-11*time.Minute), nil)
	require.NoError(t, err)
	usedChallenge, err := store.BeginChallengeWithPayload(ctx, "login", "", "used-challenge", now.Add(5*time.Minute), nil)
	require.NoError(t, err)
	freshChallenge, err := store.BeginChallengeWithPayload(ctx, "login", "", "fresh-challenge", now.Add(5*time.Minute), nil)
	require.NoError(t, err)

	ok, err := store.ConsumeChallenge(ctx, usedChallenge.ID, "login")
	require.NoError(t, err)
	require.True(t, ok)

	err = store.DeleteExpiredAuthChallenge(ctx, expiredChallenge.ID, now)
	require.NoError(t, err)
	err = store.DeleteExpiredAuthChallenge(ctx, usedChallenge.ID, now)
	require.NoError(t, err)
	err = store.DeleteExpiredAuthChallenge(ctx, freshChallenge.ID, now)
	require.NoError(t, err)

	ok, err = store.ConsumeChallenge(ctx, expiredChallenge.ID, "login")
	require.NoError(t, err)
	require.False(t, ok)

	ok, err = store.ConsumeChallenge(ctx, usedChallenge.ID, "login")
	require.NoError(t, err)
	require.False(t, ok)

	ok, err = store.ConsumeChallenge(ctx, freshChallenge.ID, "login")
	require.NoError(t, err)
	require.True(t, ok)
}

func TestAuthStoreDeleteRevokedSessionExpiredOnly(t *testing.T) {
	ctx := t.Context()
	conn := newTestDatabase(t)

	require.NoError(t, RunMigrations(ctx, conn, nil))

	store, err := NewAuthStore(conn, nil)
	require.NoError(t, err)

	oldRevokedSession, err := store.RegisterUser(ctx, RegisterUserInput{
		UserID:         "user-revoked-old",
		DisplayName:    "Old Revoked",
		WebAuthnUserID: "webauthn-user-revoked-old",
		CredentialID:   "cred-revoked-old",
		PublicKey:      `{"kty":"EC"}`,
		SignCount:      1,
		SessionTTL:     time.Minute,
	})
	require.NoError(t, err)
	tooFreshRevokedSession, err := store.RegisterUser(ctx, RegisterUserInput{
		UserID:         "user-revoked-fresh",
		DisplayName:    "Fresh Revoked",
		WebAuthnUserID: "webauthn-user-revoked-fresh",
		CredentialID:   "cred-revoked-fresh",
		PublicKey:      `{"kty":"EC"}`,
		SignCount:      1,
		SessionTTL:     time.Hour,
	})
	require.NoError(t, err)
	notRevokedSession, err := store.RegisterUser(ctx, RegisterUserInput{
		UserID:         "user-not-revoked",
		DisplayName:    "Not Revoked",
		WebAuthnUserID: "webauthn-user-not-revoked",
		CredentialID:   "cred-not-revoked",
		PublicKey:      `{"kty":"EC"}`,
		SignCount:      1,
		SessionTTL:     time.Hour,
	})
	require.NoError(t, err)

	_, err = conn.db.Exec(ctx, `UPDATE v2_user_sessions SET revoked_at = $2, expires_at = $3 WHERE id = $1`, oldRevokedSession.ID, time.Now().Add(-30*time.Minute).Unix(), time.Now().Add(time.Hour).Unix())
	require.NoError(t, err)
	_, err = conn.db.Exec(ctx, `UPDATE v2_user_sessions SET revoked_at = $2, expires_at = $3 WHERE id = $1`, tooFreshRevokedSession.ID, time.Now().Add(-5*time.Minute).Unix(), time.Now().Add(time.Hour).Unix())
	require.NoError(t, err)

	err = store.DeleteRevokedSession(ctx, oldRevokedSession.ID, time.Now().UTC(), true)
	require.NoError(t, err)
	err = store.DeleteRevokedSession(ctx, tooFreshRevokedSession.ID, time.Now().UTC(), true)
	require.NoError(t, err)
	err = store.DeleteRevokedSession(ctx, notRevokedSession.ID, time.Now().UTC(), true)
	require.NoError(t, err)

	var count int
	err = conn.db.QueryRow(ctx, `SELECT COUNT(*) FROM v2_user_sessions WHERE id = $1`, oldRevokedSession.ID).Scan(&count)
	require.NoError(t, err)
	require.Equal(t, 0, count)

	err = conn.db.QueryRow(ctx, `SELECT COUNT(*) FROM v2_user_sessions WHERE id = $1`, tooFreshRevokedSession.ID).Scan(&count)
	require.NoError(t, err)
	require.Equal(t, 1, count)

	err = conn.db.QueryRow(ctx, `SELECT COUNT(*) FROM v2_user_sessions WHERE id = $1`, notRevokedSession.ID).Scan(&count)
	require.NoError(t, err)
	require.Equal(t, 1, count)
}

func TestAuthStoreDeleteRevokedSessionImmediate(t *testing.T) {
	ctx := t.Context()
	conn := newTestDatabase(t)

	require.NoError(t, RunMigrations(ctx, conn, nil))

	store, err := NewAuthStore(conn, nil)
	require.NoError(t, err)

	revokedSession, err := store.RegisterUser(ctx, RegisterUserInput{
		UserID:         "user-revoked-now",
		DisplayName:    "Revoked Now",
		WebAuthnUserID: "webauthn-user-revoked-now",
		CredentialID:   "cred-revoked-now",
		PublicKey:      `{"kty":"EC"}`,
		SignCount:      1,
		SessionTTL:     time.Hour,
	})
	require.NoError(t, err)
	notRevokedSession, err := store.RegisterUser(ctx, RegisterUserInput{
		UserID:         "user-still-active",
		DisplayName:    "Still Active",
		WebAuthnUserID: "webauthn-user-still-active",
		CredentialID:   "cred-still-active",
		PublicKey:      `{"kty":"EC"}`,
		SignCount:      1,
		SessionTTL:     time.Hour,
	})
	require.NoError(t, err)

	err = store.RevokeSession(ctx, revokedSession.ID)
	require.NoError(t, err)

	err = store.DeleteRevokedSession(ctx, revokedSession.ID, time.Now().UTC(), false)
	require.NoError(t, err)
	err = store.DeleteRevokedSession(ctx, notRevokedSession.ID, time.Now().UTC(), false)
	require.NoError(t, err)

	got, err := store.GetSession(ctx, revokedSession.ID)
	require.NoError(t, err)
	require.Nil(t, got)

	got, err = store.GetSession(ctx, notRevokedSession.ID)
	require.NoError(t, err)
	require.NotNil(t, got)
}

func TestAuthStoreDeleteNonreadyUser(t *testing.T) {
	ctx := t.Context()
	conn := newTestDatabase(t)

	require.NoError(t, RunMigrations(ctx, conn, nil))

	store, err := NewAuthStore(conn, nil)
	require.NoError(t, err)

	nonreadyOldSession, err := store.RegisterUser(ctx, RegisterUserInput{
		UserID:         "user-nonready-old",
		DisplayName:    "Old Nonready",
		WebAuthnUserID: "webauthn-user-nonready-old",
		CredentialID:   "cred-nonready-old",
		PublicKey:      `{"kty":"EC"}`,
		SignCount:      1,
		SessionTTL:     time.Hour,
	})
	require.NoError(t, err)
	nonreadyFreshSession, err := store.RegisterUser(ctx, RegisterUserInput{
		UserID:         "user-nonready-fresh",
		DisplayName:    "Fresh Nonready",
		WebAuthnUserID: "webauthn-user-nonready-fresh",
		CredentialID:   "cred-nonready-fresh",
		PublicKey:      `{"kty":"EC"}`,
		SignCount:      1,
		SessionTTL:     time.Hour,
	})
	require.NoError(t, err)
	readySession, err := store.RegisterUser(ctx, RegisterUserInput{
		UserID:         "user-ready",
		DisplayName:    "Ready User",
		WebAuthnUserID: "webauthn-user-ready",
		CredentialID:   "cred-ready",
		PublicKey:      `{"kty":"EC"}`,
		SignCount:      1,
		SessionTTL:     time.Hour,
	})
	require.NoError(t, err)

	_, err = conn.db.Exec(ctx, `UPDATE v2_users SET created_at = $2 WHERE id = $1`, nonreadyOldSession.UserID, time.Now().Add(-25*time.Hour).Unix())
	require.NoError(t, err)
	_, err = conn.db.Exec(ctx, `UPDATE v2_users SET created_at = $2 WHERE id = $1`, nonreadyFreshSession.UserID, time.Now().Add(-23*time.Hour).Unix())
	require.NoError(t, err)
	require.NoError(t, store.FinalizeSignup(ctx, readySession.UserID, "canary-ready", `{"kty":"EC"}`, "mlkem-ready"))
	_, err = conn.db.Exec(ctx, `UPDATE v2_users SET created_at = $2 WHERE id = $1`, readySession.UserID, time.Now().Add(-25*time.Hour).Unix())
	require.NoError(t, err)

	err = store.DeleteNonreadyUser(ctx, nonreadyOldSession.UserID, time.Now().UTC())
	require.NoError(t, err)
	err = store.DeleteNonreadyUser(ctx, nonreadyFreshSession.UserID, time.Now().UTC())
	require.NoError(t, err)
	err = store.DeleteNonreadyUser(ctx, readySession.UserID, time.Now().UTC())
	require.NoError(t, err)

	user, err := store.GetUserByID(ctx, nonreadyOldSession.UserID)
	require.NoError(t, err)
	require.Nil(t, user)

	user, err = store.GetUserByID(ctx, nonreadyFreshSession.UserID)
	require.NoError(t, err)
	require.NotNil(t, user)
	require.False(t, user.Ready)

	user, err = store.GetUserByID(ctx, readySession.UserID)
	require.NoError(t, err)
	require.NotNil(t, user)
	require.True(t, user.Ready)
}

func TestAuthStoreUpdateDisplayName(t *testing.T) {
	ctx := t.Context()
	conn := newTestDatabase(t)

	require.NoError(t, RunMigrations(ctx, conn, nil))

	store, err := NewAuthStore(conn, nil)
	require.NoError(t, err)

	_, err = store.RegisterUser(ctx, RegisterUserInput{
		UserID:         "user-1",
		DisplayName:    "Alice",
		WebAuthnUserID: "webauthn-user-1",
		CredentialID:   "cred-1",
		PublicKey:      `{"kty":"EC"}`,
		SignCount:      1,
		SessionTTL:     time.Minute,
	})
	require.NoError(t, err)
	require.NoError(t, store.FinalizeSignup(ctx, "user-1", "", `{"kty":"EC"}`, "mlkem-pub"))

	// Successful update
	err = store.UpdateDisplayName(ctx, "user-1", "Bob")
	require.NoError(t, err)
	user, err := store.GetUserByID(ctx, "user-1")
	require.NoError(t, err)
	require.Equal(t, "Bob", user.DisplayName)

	// Empty display name is valid
	err = store.UpdateDisplayName(ctx, "user-1", "")
	require.NoError(t, err)
	user, err = store.GetUserByID(ctx, "user-1")
	require.NoError(t, err)
	require.Empty(t, user.DisplayName)

	// Too-long display name
	err = store.UpdateDisplayName(ctx, "user-1", strings.Repeat("a", 101))
	require.ErrorIs(t, err, ErrDisplayNameTooLong)

	// Non-existent user
	err = store.UpdateDisplayName(ctx, "no-such-user", "Test")
	require.ErrorIs(t, err, ErrUserNotFound)
}

func TestAuthStoreUpdateWrappedPrimaryKey(t *testing.T) {
	ctx := t.Context()
	conn := newTestDatabase(t)

	require.NoError(t, RunMigrations(ctx, conn, nil))

	store, err := NewAuthStore(conn, nil)
	require.NoError(t, err)

	_, err = store.RegisterUser(ctx, RegisterUserInput{
		UserID:         "user-1",
		DisplayName:    "Alice",
		WebAuthnUserID: "webauthn-user-1",
		CredentialID:   "cred-1",
		PublicKey:      `{"kty":"EC"}`,
		SignCount:      1,
		SessionTTL:     time.Minute,
	})
	require.NoError(t, err)
	require.NoError(t, store.FinalizeSignup(ctx, "user-1", "initial-key", `{"kty":"EC"}`, "mlkem-pub"))

	// Successful update
	err = store.UpdateWrappedPrimaryKey(ctx, "user-1", "new-wrapped-key")
	require.NoError(t, err)
	user, err := store.GetUserByID(ctx, "user-1")
	require.NoError(t, err)
	require.Equal(t, "new-wrapped-key", user.WrappedPrimaryKey)

	// Empty string is valid (removes password)
	err = store.UpdateWrappedPrimaryKey(ctx, "user-1", "")
	require.NoError(t, err)
	user, err = store.GetUserByID(ctx, "user-1")
	require.NoError(t, err)
	require.Empty(t, user.WrappedPrimaryKey)

	// Oversized value
	err = store.UpdateWrappedPrimaryKey(ctx, "user-1", strings.Repeat("x", 513))
	require.Error(t, err)
	require.Contains(t, err.Error(), "too large")

	// Non-existent user
	err = store.UpdateWrappedPrimaryKey(ctx, "no-such-user", "key")
	require.ErrorIs(t, err, ErrUserNotFound)
}

func TestAuthStoreCredentialCRUD(t *testing.T) {
	ctx := t.Context()
	conn := newTestDatabase(t)

	require.NoError(t, RunMigrations(ctx, conn, nil))

	store, err := NewAuthStore(conn, nil)
	require.NoError(t, err)

	_, err = store.RegisterUser(ctx, RegisterUserInput{
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
	creds, err := store.ListCredentials(ctx, "user-1")
	require.NoError(t, err)
	require.Len(t, creds, 1)
	require.NotEmpty(t, creds[0].ID)
	require.Equal(t, "cred-1", creds[0].CredentialID)
	require.Equal(t, "My Laptop", creds[0].DisplayName)
	require.NotZero(t, creds[0].CreatedAt)
	require.NotZero(t, creds[0].LastUsedAt)

	firstCredID := creds[0].ID

	// Add a second credential
	err = store.AddCredential(ctx, AddCredentialInput{
		UserID:       "user-1",
		CredentialID: "cred-2",
		DisplayName:  "My Phone",
		PublicKey:    `{"kty":"EC","crv":"P-256"}`,
		SignCount:    0,
	})
	require.NoError(t, err)

	creds, err = store.ListCredentials(ctx, "user-1")
	require.NoError(t, err)
	require.Len(t, creds, 2)

	secondCredID := creds[1].ID
	require.Equal(t, "My Phone", creds[1].DisplayName)

	// Rename second credential
	err = store.RenameCredential(ctx, secondCredID, "user-1", "Work Phone")
	require.NoError(t, err)
	creds, err = store.ListCredentials(ctx, "user-1")
	require.NoError(t, err)
	require.Equal(t, "Work Phone", creds[1].DisplayName)

	// Rename with too-long name
	err = store.RenameCredential(ctx, secondCredID, "user-1", strings.Repeat("a", 101))
	require.ErrorIs(t, err, ErrDisplayNameTooLong)

	// Rename nonexistent credential
	err = store.RenameCredential(ctx, "nonexistent-id", "user-1", "test")
	require.ErrorIs(t, err, ErrCredentialNotFound)

	// Rename credential belonging to different user
	err = store.RenameCredential(ctx, secondCredID, "other-user", "test")
	require.ErrorIs(t, err, ErrCredentialNotFound)

	// Delete second credential — should succeed
	err = store.DeleteCredential(ctx, secondCredID, "user-1")
	require.NoError(t, err)
	creds, err = store.ListCredentials(ctx, "user-1")
	require.NoError(t, err)
	require.Len(t, creds, 1)
	require.Equal(t, firstCredID, creds[0].ID)

	// Delete last credential — should fail
	err = store.DeleteCredential(ctx, firstCredID, "user-1")
	require.ErrorIs(t, err, ErrLastCredential)

	// Delete nonexistent credential
	err = store.DeleteCredential(ctx, "nonexistent-id", "user-1")
	require.ErrorIs(t, err, ErrLastCredential)
}
