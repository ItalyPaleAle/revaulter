package v2db

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestAuthStoreFirstAdminAndLoginSQLite(t *testing.T) {
	ctx := context.Background()
	conn, _, err := Open(ctx, t.TempDir()+"/auth.db")
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	store, err := NewAuthStore(ctx, conn, nil)
	require.NoError(t, err)

	n, err := store.CountAdmins(ctx)
	require.NoError(t, err)
	require.Equal(t, 0, n)

	ch, err := store.BeginChallenge(ctx, "register", "alice", time.Minute)
	require.NoError(t, err)
	require.NotEmpty(t, ch.Challenge)

	ok, err := store.ConsumeChallenge(ctx, ch.ID, "register", "alice")
	require.NoError(t, err)
	require.True(t, ok)

	sess, err := store.RegisterFirstAdmin(ctx, RegisterFirstAdminInput{
		Username:     "alice",
		DisplayName:  "Alice",
		CredentialID: "cred-1",
		PublicKey:    `{"kty":"EC"}`,
		SignCount:    1,
		SessionTTL:   time.Minute,
	})
	require.NoError(t, err)
	require.NotNil(t, sess)

	// Second first-admin registration must fail.
	_, err = store.RegisterFirstAdmin(ctx, RegisterFirstAdminInput{
		Username:     "bob",
		DisplayName:  "Bob",
		CredentialID: "cred-2",
		PublicKey:    `{"kty":"EC"}`,
	})
	require.ErrorIs(t, err, ErrFirstAdminAlreadyExists)

	loginCh, err := store.BeginChallenge(ctx, "login", "alice", time.Minute)
	require.NoError(t, err)
	ok, err = store.ConsumeChallenge(ctx, loginCh.ID, "login", "alice")
	require.NoError(t, err)
	require.True(t, ok)

	loginSess, err := store.Login(ctx, LoginInput{
		Username:     "alice",
		CredentialID: "cred-1",
		SignCount:    2,
		SessionTTL:   time.Minute,
	})
	require.NoError(t, err)
	require.NotNil(t, loginSess)
	require.NotEqual(t, sess.ID, loginSess.ID)

	got, err := store.GetSession(ctx, loginSess.ID)
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Equal(t, "alice", got.Username)
	require.False(t, got.PasswordVerified)

	err = store.RevokeSession(ctx, loginSess.ID)
	require.NoError(t, err)
	got, err = store.GetSession(ctx, loginSess.ID)
	require.NoError(t, err)
	require.Nil(t, got)
}

func TestAuthStorePasswordFactorSessionFlagSQLite(t *testing.T) {
	ctx := context.Background()
	conn, _, err := Open(ctx, t.TempDir()+"/auth2.db")
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	store, err := NewAuthStore(ctx, conn, nil)
	require.NoError(t, err)

	_, err = store.RegisterFirstAdmin(ctx, RegisterFirstAdminInput{
		Username:     "alice",
		DisplayName:  "Alice",
		CredentialID: "cred-1",
		PublicKey:    `{"kty":"EC"}`,
		SignCount:    1,
		PasswordFactor: &PasswordFactorEnrollment{
			Salt:       "c2FsdA",
			Iterations: 300000,
			AuthKey:    "YXV0aGtleQ",
		},
		SessionTTL: time.Minute,
	})
	require.NoError(t, err)

	pf, err := store.GetPasswordFactorByUsername(ctx, "alice")
	require.NoError(t, err)
	require.NotNil(t, pf)
	require.Equal(t, 300000, pf.Iterations)
	require.True(t, pf.Enabled)

	sess, err := store.Login(ctx, LoginInput{
		Username:         "alice",
		CredentialID:     "cred-1",
		SignCount:        2,
		PasswordVerified: true,
		SessionTTL:       time.Minute,
	})
	require.NoError(t, err)
	got, err := store.GetSession(ctx, sess.ID)
	require.NoError(t, err)
	require.NotNil(t, got)
	require.True(t, got.PasswordVerified)
}

func TestAuthStorePasswordFactorEncryptedAtRestSQLite(t *testing.T) {
	ctx := context.Background()
	conn, _, err := Open(ctx, t.TempDir()+"/auth3.db")
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	key := []byte("0123456789abcdef0123456789abcdef")
	store, err := NewAuthStoreWithPayloadKey(ctx, conn, key, nil)
	require.NoError(t, err)

	_, err = store.RegisterFirstAdmin(ctx, RegisterFirstAdminInput{
		Username:     "alice",
		DisplayName:  "Alice",
		CredentialID: "cred-1",
		PublicKey:    `{"kty":"EC"}`,
		SignCount:    1,
		PasswordFactor: &PasswordFactorEnrollment{
			Salt:       "c2FsdA",
			Iterations: 300000,
			AuthKey:    "YXV0aGtleQ",
		},
		SessionTTL: time.Minute,
	})
	require.NoError(t, err)

	var raw string
	err = conn.SQLite.QueryRowContext(ctx, `SELECT auth_key FROM v2_admin_password_factors LIMIT 1`).Scan(&raw)
	require.NoError(t, err)
	require.NotContains(t, raw, "YXV0aGtleQ")
	require.Contains(t, raw, "enc:")

	pf, err := store.GetPasswordFactorByUsername(ctx, "alice")
	require.NoError(t, err)
	require.NotNil(t, pf)
	require.Equal(t, "YXV0aGtleQ", pf.AuthKey)
}

func TestVerifyPasswordProof(t *testing.T) {
	key := []byte("auth-key")
	msg := []byte("message")
	m := hmac.New(sha256.New, key)
	_, _ = m.Write(msg)
	proof := base64.RawURLEncoding.EncodeToString(m.Sum(nil))
	require.True(t, VerifyPasswordProof(base64.RawURLEncoding.EncodeToString(key), proof, msg))
	require.False(t, VerifyPasswordProof(base64.RawURLEncoding.EncodeToString(key), "bad", msg))
}
