package v2db

import (
	"context"
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

	err = store.RevokeSession(ctx, loginSess.ID)
	require.NoError(t, err)
	got, err = store.GetSession(ctx, loginSess.ID)
	require.NoError(t, err)
	require.Nil(t, got)
}

