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

func TestSigningKeyStoreStoreAutoDerivedIfMissingInsertsUnpublished(t *testing.T) {
	ctx := t.Context()
	conn := newTestDatabase(t)
	require.NoError(t, RunMigrations(ctx, conn, nil))

	authStore, err := NewAuthStore(conn, nil)
	require.NoError(t, err)
	newSigningKeyTestUser(t, authStore, "frank")

	store, err := NewSigningKeyStore(conn, nil)
	require.NoError(t, err)

	inserted, err := store.StoreAutoDerivedIfMissing(ctx, StoreAutoDerivedSigningKeyInput{
		ID:        "id-auto",
		UserID:    "frank",
		Algorithm: "ES256",
		KeyLabel:  "auto-label",
		JWK:       `{"kty":"EC","crv":"P-256","x":"X","y":"Y"}`,
		PEM:       "-----BEGIN PUBLIC KEY-----\nAAA\n-----END PUBLIC KEY-----",
	})
	require.NoError(t, err)
	require.True(t, inserted, "first auto-store call for a new (user, algorithm, label) must insert")

	rec, err := store.GetByID(ctx, "id-auto")
	require.NoError(t, err)
	require.NotNil(t, rec)
	require.Equal(t, "frank", rec.UserID)
	require.Equal(t, "ES256", rec.Algorithm)
	require.Equal(t, "auto-label", rec.KeyLabel)
	require.False(t, rec.Published, "auto-stored rows must start as published=false")
	require.Equal(t, rec.CreatedAt.Unix(), rec.UpdatedAt.Unix(), "created_at and updated_at must match on insert")

	// An auto-stored row is not served from the published-only getter
	pub, err := store.GetPublishedByID(ctx, "id-auto")
	require.NoError(t, err)
	require.Nil(t, pub, "GetPublishedByID must hide auto-stored rows until they are published")
}

func TestSigningKeyStoreStoreAutoDerivedIfMissingNoOpWhenAutoStored(t *testing.T) {
	ctx := t.Context()
	conn := newTestDatabase(t)
	require.NoError(t, RunMigrations(ctx, conn, nil))

	authStore, err := NewAuthStore(conn, nil)
	require.NoError(t, err)
	newSigningKeyTestUser(t, authStore, "gina")

	store, err := NewSigningKeyStore(conn, nil)
	require.NoError(t, err)

	first := StoreAutoDerivedSigningKeyInput{
		ID:        "id-first",
		UserID:    "gina",
		Algorithm: "ES256",
		KeyLabel:  "shared-label",
		JWK:       `{"first":true}`,
		PEM:       "first-pem",
	}
	inserted, err := store.StoreAutoDerivedIfMissing(ctx, first)
	require.NoError(t, err)
	require.True(t, inserted)

	rec1, err := store.GetByID(ctx, "id-first")
	require.NoError(t, err)
	require.NotNil(t, rec1)
	updatedAt1 := rec1.UpdatedAt.Unix()

	// Sleep past the 1-second unix-time resolution so a missed update would be observable
	time.Sleep(1_100 * time.Millisecond)

	// A second call with different material under the same (user, algorithm, label) must not overwrite the existing row
	inserted, err = store.StoreAutoDerivedIfMissing(ctx, StoreAutoDerivedSigningKeyInput{
		ID:        "id-second",
		UserID:    "gina",
		Algorithm: "ES256",
		KeyLabel:  "shared-label",
		JWK:       `{"second":true}`,
		PEM:       "second-pem",
	})
	require.NoError(t, err)
	require.False(t, inserted, "second auto-store call for an existing row must report no insert")

	// The would-be new id does not exist, the original row is unchanged
	recSecond, err := store.GetByID(ctx, "id-second")
	require.NoError(t, err)
	require.Nil(t, recSecond)

	rec1Again, err := store.GetByID(ctx, "id-first")
	require.NoError(t, err)
	require.NotNil(t, rec1Again)
	require.Equal(t, `{"first":true}`, rec1Again.JWK)
	require.Equal(t, "first-pem", rec1Again.PEM)
	require.False(t, rec1Again.Published)
	require.Equal(t, updatedAt1, rec1Again.UpdatedAt.Unix(), "updated_at must not move when the insert is skipped")
}

func TestSigningKeyStoreStoreAutoDerivedIfMissingNoOpWhenPublished(t *testing.T) {
	ctx := t.Context()
	conn := newTestDatabase(t)
	require.NoError(t, RunMigrations(ctx, conn, nil))

	authStore, err := NewAuthStore(conn, nil)
	require.NoError(t, err)
	newSigningKeyTestUser(t, authStore, "henry")

	store, err := NewSigningKeyStore(conn, nil)
	require.NoError(t, err)

	// Pre-publish via the normal path, then attempt to auto-store the same (user, algorithm, label)
	require.NoError(t, store.Upsert(ctx, UpsertPublishedSigningKeyInput{
		ID:        "id-pub",
		UserID:    "henry",
		Algorithm: "ES256",
		KeyLabel:  "keep-published",
		JWK:       `{"pub":true}`,
		PEM:       "pub-pem",
	}))

	inserted, err := store.StoreAutoDerivedIfMissing(ctx, StoreAutoDerivedSigningKeyInput{
		ID:        "id-auto",
		UserID:    "henry",
		Algorithm: "ES256",
		KeyLabel:  "keep-published",
		JWK:       `{"auto":true}`,
		PEM:       "auto-pem",
	})
	require.NoError(t, err)
	require.False(t, inserted, "auto-store must not touch a row that is already published")

	rec, err := store.GetByID(ctx, "id-pub")
	require.NoError(t, err)
	require.NotNil(t, rec)
	require.True(t, rec.Published, "published row must stay published")
	require.Equal(t, `{"pub":true}`, rec.JWK, "published material must not be overwritten by auto-store")
}

func TestSigningKeyStoreStoreAutoDerivedIfMissingScopedPerUserAlgorithmLabel(t *testing.T) {
	ctx := t.Context()
	conn := newTestDatabase(t)
	require.NoError(t, RunMigrations(ctx, conn, nil))

	authStore, err := NewAuthStore(conn, nil)
	require.NoError(t, err)
	newSigningKeyTestUser(t, authStore, "ivan")
	newSigningKeyTestUser(t, authStore, "judy")

	store, err := NewSigningKeyStore(conn, nil)
	require.NoError(t, err)

	// Same (algorithm, label) for two different users must both insert — the unique index is (user_id, algorithm, key_label)
	insertedIvan, err := store.StoreAutoDerivedIfMissing(ctx, StoreAutoDerivedSigningKeyInput{
		ID: "id-ivan", UserID: "ivan", Algorithm: "ES256", KeyLabel: "shared",
		JWK: `{}`, PEM: "pem",
	})
	require.NoError(t, err)
	require.True(t, insertedIvan)

	insertedJudy, err := store.StoreAutoDerivedIfMissing(ctx, StoreAutoDerivedSigningKeyInput{
		ID: "id-judy", UserID: "judy", Algorithm: "ES256", KeyLabel: "shared",
		JWK: `{}`, PEM: "pem",
	})
	require.NoError(t, err)
	require.True(t, insertedJudy, "second user with the same algorithm+label must still get a row")

	// Same user with a different algorithm under the same label must also insert
	insertedES384, err := store.StoreAutoDerivedIfMissing(ctx, StoreAutoDerivedSigningKeyInput{
		ID: "id-ivan-es384", UserID: "ivan", Algorithm: "ES384", KeyLabel: "shared",
		JWK: `{}`, PEM: "pem",
	})
	require.NoError(t, err)
	require.True(t, insertedES384, "same user with a different algorithm must still get a row")
}

func TestSigningKeyStoreUpsertPromotesAutoStored(t *testing.T) {
	ctx := t.Context()
	conn := newTestDatabase(t)
	require.NoError(t, RunMigrations(ctx, conn, nil))

	authStore, err := NewAuthStore(conn, nil)
	require.NoError(t, err)
	newSigningKeyTestUser(t, authStore, "kate")

	store, err := NewSigningKeyStore(conn, nil)
	require.NoError(t, err)

	// Auto-store first (published=false), then publish via Upsert with the same id — the conflict path in Upsert must flip published to true
	inserted, err := store.StoreAutoDerivedIfMissing(ctx, StoreAutoDerivedSigningKeyInput{
		ID:        "id-k",
		UserID:    "kate",
		Algorithm: "ES256",
		KeyLabel:  "promoteme",
		JWK:       `{"x":1}`,
		PEM:       "pem",
	})
	require.NoError(t, err)
	require.True(t, inserted)

	rec, err := store.GetByID(ctx, "id-k")
	require.NoError(t, err)
	require.NotNil(t, rec)
	require.False(t, rec.Published)

	// GetPublishedByID must not surface an auto-stored row
	pub, err := store.GetPublishedByID(ctx, "id-k")
	require.NoError(t, err)
	require.Nil(t, pub)

	require.NoError(t, store.Upsert(ctx, UpsertPublishedSigningKeyInput{
		ID:        "id-k",
		UserID:    "kate",
		Algorithm: "ES256",
		KeyLabel:  "promoteme",
		JWK:       `{"x":1}`,
		PEM:       "pem",
	}))

	recAfter, err := store.GetByID(ctx, "id-k")
	require.NoError(t, err)
	require.NotNil(t, recAfter)
	require.True(t, recAfter.Published, "Upsert must promote an auto-stored row to published=true")

	pubAfter, err := store.GetPublishedByID(ctx, "id-k")
	require.NoError(t, err)
	require.NotNil(t, pubAfter, "after publish the row must be visible from GetPublishedByID")
}
