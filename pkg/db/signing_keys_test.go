package db

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func newSigningKeyTestUser(t *testing.T, auth *AuthStore, userID string) {
	t.Helper()
	_, err := auth.RegisterUser(t.Context(), RegisterUserInput{
		UserID:         userID,
		DisplayName:    userID,
		WebAuthnUserID: "webauthn-" + userID,
		CredentialID:   "cred-" + userID,
		PublicKey:      `{"kty":"EC"}`,
		SignCount:      1,
		SessionTTL:     time.Minute,
	})
	require.NoError(t, err)
}

func TestSigningKeyStoreUpsertIdempotent(t *testing.T) {
	ctx := t.Context()
	conn := newTestDatabase(t)
	require.NoError(t, RunMigrations(ctx, conn, nil))

	authStore, err := NewAuthStore(conn, nil)
	require.NoError(t, err)
	newSigningKeyTestUser(t, authStore, "alice")

	store, err := NewSigningKeyStore(conn, nil)
	require.NoError(t, err)

	in := UpsertPublishedSigningKeyInput{
		ID:        "id-1",
		UserID:    "alice",
		Algorithm: "ES256",
		KeyLabel:  "payments",
		JWK:       `{"kty":"EC","crv":"P-256","x":"X","y":"Y"}`,
		PEM:       "-----BEGIN PUBLIC KEY-----\nAAA\n-----END PUBLIC KEY-----",
	}

	require.NoError(t, store.Upsert(ctx, in))
	rec1, err := store.GetByID(ctx, "id-1")
	require.NoError(t, err)
	require.NotNil(t, rec1)
	require.Equal(t, "ES256", rec1.Algorithm)
	require.Equal(t, "payments", rec1.KeyLabel)
	createdAt1 := rec1.CreatedAt
	updatedAt1 := rec1.UpdatedAt

	// Sleep past the 1-second unix-time resolution so updated_at can visibly advance when the UPSERT runs again
	time.Sleep(1_100 * time.Millisecond)

	// Re-publishing the same material yields the same id and replaces the row
	require.NoError(t, store.Upsert(ctx, in))
	rec2, err := store.GetByID(ctx, "id-1")
	require.NoError(t, err)
	require.NotNil(t, rec2)
	require.Equal(t, createdAt1.Unix(), rec2.CreatedAt.Unix(), "created_at must be preserved across UPSERT")
	require.Greater(t, rec2.UpdatedAt.Unix(), updatedAt1.Unix(), "updated_at must move forward")
}

func TestSigningKeyStoreUpsertReplacesSameLabel(t *testing.T) {
	ctx := t.Context()
	conn := newTestDatabase(t)
	require.NoError(t, RunMigrations(ctx, conn, nil))

	authStore, err := NewAuthStore(conn, nil)
	require.NoError(t, err)
	newSigningKeyTestUser(t, authStore, "bob")

	store, err := NewSigningKeyStore(conn, nil)
	require.NoError(t, err)

	// Publish two different keys under the same (user, algorithm, key label); only the newest row should remain, the previous id must disappear
	require.NoError(t, store.Upsert(ctx, UpsertPublishedSigningKeyInput{
		ID: "id-old", UserID: "bob", Algorithm: "ES256", KeyLabel: "main",
		JWK: `{"old":true}`, PEM: "old",
	}))
	require.NoError(t, store.Upsert(ctx, UpsertPublishedSigningKeyInput{
		ID: "id-new", UserID: "bob", Algorithm: "ES256", KeyLabel: "main",
		JWK: `{"new":true}`, PEM: "new",
	}))

	recOld, err := store.GetByID(ctx, "id-old")
	require.NoError(t, err)
	require.Nil(t, recOld, "previous row must be gone — enforced by unique index on (user_id, algorithm, key_label)")

	recNew, err := store.GetByID(ctx, "id-new")
	require.NoError(t, err)
	require.NotNil(t, recNew)
	require.Equal(t, `{"new":true}`, recNew.JWK)
	require.Equal(t, "new", recNew.PEM)
}

func TestSigningKeyStoreListForUser(t *testing.T) {
	ctx := t.Context()
	conn := newTestDatabase(t)
	require.NoError(t, RunMigrations(ctx, conn, nil))

	authStore, err := NewAuthStore(conn, nil)
	require.NoError(t, err)
	newSigningKeyTestUser(t, authStore, "carol")
	newSigningKeyTestUser(t, authStore, "dave")

	store, err := NewSigningKeyStore(conn, nil)
	require.NoError(t, err)

	require.NoError(t, store.Upsert(ctx, UpsertPublishedSigningKeyInput{
		ID: "id-c2", UserID: "carol", Algorithm: "ES256", KeyLabel: "zeta",
		JWK: `{}`, PEM: "pem",
	}))
	require.NoError(t, store.Upsert(ctx, UpsertPublishedSigningKeyInput{
		ID: "id-c1", UserID: "carol", Algorithm: "ES256", KeyLabel: "alpha",
		JWK: `{}`, PEM: "pem",
	}))
	require.NoError(t, store.Upsert(ctx, UpsertPublishedSigningKeyInput{
		ID: "id-d", UserID: "dave", Algorithm: "ES256", KeyLabel: "alpha",
		JWK: `{}`, PEM: "pem",
	}))

	items, err := store.ListForUser(ctx, "carol")
	require.NoError(t, err)
	require.Len(t, items, 2)
	// Sorted by algorithm asc, key_label asc
	require.Equal(t, "alpha", items[0].KeyLabel)
	require.Equal(t, "zeta", items[1].KeyLabel)

	// Listing does not leak another user's records
	for _, item := range items {
		require.NotEqual(t, "id-d", item.ID)
	}

	empty, err := store.ListForUser(ctx, "no-such-user")
	require.NoError(t, err)
	require.Empty(t, empty)
}

func TestSigningKeyStoreDelete(t *testing.T) {
	ctx := t.Context()
	conn := newTestDatabase(t)
	require.NoError(t, RunMigrations(ctx, conn, nil))

	authStore, err := NewAuthStore(conn, nil)
	require.NoError(t, err)
	newSigningKeyTestUser(t, authStore, "erin")
	newSigningKeyTestUser(t, authStore, "mallory")

	store, err := NewSigningKeyStore(conn, nil)
	require.NoError(t, err)
	require.NoError(t, store.Upsert(ctx, UpsertPublishedSigningKeyInput{
		ID: "id-e", UserID: "erin", Algorithm: "ES256", KeyLabel: "k",
		JWK: `{}`, PEM: "pem",
	}))

	// Another user cannot delete erin's key even if they know the id
	deleted, err := store.Delete(ctx, "mallory", "id-e")
	require.NoError(t, err)
	require.False(t, deleted)

	rec, err := store.GetByID(ctx, "id-e")
	require.NoError(t, err)
	require.NotNil(t, rec)

	deleted, err = store.Delete(ctx, "erin", "id-e")
	require.NoError(t, err)
	require.True(t, deleted)

	rec, err = store.GetByID(ctx, "id-e")
	require.NoError(t, err)
	require.Nil(t, rec, "hard-delete semantics — the row must be fully gone")

	// Second delete is a no-op
	deleted, err = store.Delete(ctx, "erin", "id-e")
	require.NoError(t, err)
	require.False(t, deleted)
}

func TestSigningKeyStoreGetByIDNotFoundReturnsNil(t *testing.T) {
	ctx := t.Context()
	conn := newTestDatabase(t)
	require.NoError(t, RunMigrations(ctx, conn, nil))

	store, err := NewSigningKeyStore(conn, nil)
	require.NoError(t, err)

	rec, err := store.GetByID(ctx, "unknown-id")
	require.NoError(t, err)
	require.Nil(t, rec)
}
