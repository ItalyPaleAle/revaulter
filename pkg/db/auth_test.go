package db

import (
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
