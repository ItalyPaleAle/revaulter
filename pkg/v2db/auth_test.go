package v2db

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestAuthStoreRegisterUserAndLoginSQLite(t *testing.T) {
	ctx := t.Context()
	conn := newTestDatabase(t)

	require.NoError(t, RunMigrations(ctx, conn, nil))

	store, err := NewAuthStore(conn, nil)
	require.NoError(t, err)

	n, err := store.CountUsers(ctx)
	require.NoError(t, err)
	require.Equal(t, 0, n)

	ch, err := store.BeginChallenge(ctx, "register", "alice", time.Minute)
	require.NoError(t, err)
	require.NotEmpty(t, ch.Challenge)

	ok, err := store.ConsumeChallenge(ctx, ch.ID, "register", "alice")
	require.NoError(t, err)
	require.True(t, ok)

	sess, err := store.RegisterUser(ctx, RegisterUserInput{
		Username:     "alice",
		DisplayName:  "Alice",
		CredentialID: "cred-1",
		PublicKey:    `{"kty":"EC"}`,
		SignCount:    1,
		SessionTTL:   time.Minute,
	})
	require.NoError(t, err)
	require.NotNil(t, sess)

	// Duplicate usernames must fail
	_, err = store.RegisterUser(ctx, RegisterUserInput{
		Username:     "alice",
		DisplayName:  "Alice Again",
		CredentialID: "cred-2",
		PublicKey:    `{"kty":"EC"}`,
		SessionTTL:   time.Minute,
	})
	require.ErrorIs(t, err, ErrUserAlreadyExists)

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
