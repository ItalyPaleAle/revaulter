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

func TestSigningKeyStoreInsertIdempotentNoOp(t *testing.T) {
	ctx := t.Context()
	conn := newTestDatabase(t)
	require.NoError(t, RunMigrations(ctx, conn, nil))

	authStore, err := NewAuthStore(conn)
	require.NoError(t, err)
	newSigningKeyTestUser(t, authStore, "alice")

	store, err := NewSigningKeyStore(conn)
	require.NoError(t, err)

	in := InsertSigningKeyInput{
		ID:        "id-1",
		UserID:    "alice",
		Algorithm: "ES256",
		KeyLabel:  "payments",
		JWK:       `{"kty":"EC","crv":"P-256","x":"X","y":"Y"}`,
		PEM:       "-----BEGIN PUBLIC KEY-----\nAAA\n-----END PUBLIC KEY-----",
		Published: true,
	}

	inserted, err := store.Create(ctx, in)
	require.NoError(t, err)
	require.NotNil(t, inserted, "first insert for a new (user, algorithm, label) must return the inserted row")
	require.Equal(t, "ES256", inserted.Algorithm)
	require.Equal(t, "payments", inserted.KeyLabel)

	rec1, err := store.GetByID(ctx, "id-1")
	require.NoError(t, err)
	require.NotNil(t, rec1)
	require.Equal(t, "ES256", rec1.Algorithm)
	require.Equal(t, "payments", rec1.KeyLabel)
	createdAt1 := rec1.CreatedAt
	updatedAt1 := rec1.UpdatedAt

	// Sleep past the 1-second unix-time resolution so a missed update would be observable on updated_at
	time.Sleep(1_100 * time.Millisecond)

	// A second insert for the same (user, algorithm, label) must fail with ErrSigningKeyAlreadyExists and leave the row untouched
	inserted, err = store.Create(ctx, in)
	require.ErrorIs(t, err, ErrSigningKeyAlreadyExists, "duplicate insert must return ErrSigningKeyAlreadyExists")
	require.Nil(t, inserted)

	rec2, err := store.GetByID(ctx, "id-1")
	require.NoError(t, err)
	require.NotNil(t, rec2)
	require.Equal(t, createdAt1.Unix(), rec2.CreatedAt.Unix(), "created_at must not change on duplicate insert")
	require.Equal(t, updatedAt1.Unix(), rec2.UpdatedAt.Unix(), "updated_at must not move on duplicate insert")
}

func TestSigningKeyStoreInsertRejectsConflictingMaterial(t *testing.T) {
	ctx := t.Context()
	conn := newTestDatabase(t)
	require.NoError(t, RunMigrations(ctx, conn, nil))

	authStore, err := NewAuthStore(conn)
	require.NoError(t, err)
	newSigningKeyTestUser(t, authStore, "bob")

	store, err := NewSigningKeyStore(conn)
	require.NoError(t, err)

	// Insert-only semantics: a second call with different material under the same (user, algorithm, label) must not overwrite the first row
	inserted, err := store.Create(ctx, InsertSigningKeyInput{
		ID: "id-old", UserID: "bob", Algorithm: "ES256", KeyLabel: "main",
		JWK: `{"old":true}`, PEM: "old", Published: true,
	})
	require.NoError(t, err)
	require.NotNil(t, inserted)

	inserted, err = store.Create(ctx, InsertSigningKeyInput{
		ID: "id-new", UserID: "bob", Algorithm: "ES256", KeyLabel: "main",
		JWK: `{"new":true}`, PEM: "new", Published: true,
	})
	require.ErrorIs(t, err, ErrSigningKeyAlreadyExists, "second insert with different material must be rejected")
	require.Nil(t, inserted)

	recOld, err := store.GetByID(ctx, "id-old")
	require.NoError(t, err)
	require.NotNil(t, recOld, "original row must remain")
	require.Equal(t, `{"old":true}`, recOld.JWK)

	recNew, err := store.GetByID(ctx, "id-new")
	require.NoError(t, err)
	require.Nil(t, recNew, "new material must not have been stored")
}

func TestSigningKeyStoreListForUser(t *testing.T) {
	ctx := t.Context()
	conn := newTestDatabase(t)
	require.NoError(t, RunMigrations(ctx, conn, nil))

	authStore, err := NewAuthStore(conn)
	require.NoError(t, err)
	newSigningKeyTestUser(t, authStore, "carol")
	newSigningKeyTestUser(t, authStore, "dave")

	store, err := NewSigningKeyStore(conn)
	require.NoError(t, err)

	_, err = store.Create(ctx, InsertSigningKeyInput{
		ID: "id-c2", UserID: "carol", Algorithm: "ES256", KeyLabel: "zeta",
		JWK: `{}`, PEM: "pem", Published: true,
	})
	require.NoError(t, err)
	_, err = store.Create(ctx, InsertSigningKeyInput{
		ID: "id-c1", UserID: "carol", Algorithm: "ES256", KeyLabel: "alpha",
		JWK: `{}`, PEM: "pem", Published: true,
	})
	require.NoError(t, err)
	_, err = store.Create(ctx, InsertSigningKeyInput{
		ID: "id-d", UserID: "dave", Algorithm: "ES256", KeyLabel: "alpha",
		JWK: `{}`, PEM: "pem", Published: true,
	})
	require.NoError(t, err)

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

func TestSigningKeyStoreSetPublished(t *testing.T) {
	ctx := t.Context()
	conn := newTestDatabase(t)
	require.NoError(t, RunMigrations(ctx, conn, nil))

	authStore, err := NewAuthStore(conn)
	require.NoError(t, err)
	newSigningKeyTestUser(t, authStore, "erin")
	newSigningKeyTestUser(t, authStore, "mallory")

	store, err := NewSigningKeyStore(conn)
	require.NoError(t, err)
	_, err = store.Create(ctx, InsertSigningKeyInput{
		ID: "id-e", UserID: "erin", Algorithm: "ES256", KeyLabel: "k",
		JWK: `{}`, PEM: "pem", Published: true,
	})
	require.NoError(t, err)

	// Another user cannot flip erin's key even if they know the id
	updated, err := store.SetPublished(ctx, "mallory", "id-e", false)
	require.ErrorIs(t, err, ErrSigningKeyNotFound)
	require.Nil(t, updated)

	rec, err := store.GetByID(ctx, "id-e")
	require.NoError(t, err)
	require.NotNil(t, rec)
	require.True(t, rec.Published, "cross-user update must not flip the flag")

	// Sleep past the 1-second unix-time resolution so updated_at can visibly advance
	time.Sleep(1_100 * time.Millisecond)

	// Erin unpublishes her own key — the row stays but published becomes false
	updated, err = store.SetPublished(ctx, "erin", "id-e", false)
	require.NoError(t, err)
	require.NotNil(t, updated, "SetPublished must return the updated row")
	require.False(t, updated.Published)
	require.Greater(t, updated.UpdatedAt.Unix(), updated.CreatedAt.Unix(), "updated_at must advance on SetPublished")

	rec, err = store.GetByID(ctx, "id-e")
	require.NoError(t, err)
	require.NotNil(t, rec, "SetPublished must not delete the row")
	require.False(t, rec.Published)

	// Re-publishing the same row brings it back via the public endpoint
	updated, err = store.SetPublished(ctx, "erin", "id-e", true)
	require.NoError(t, err)
	require.NotNil(t, updated)
	require.True(t, updated.Published)

	pub, err := store.GetPublishedByID(ctx, "id-e")
	require.NoError(t, err)
	require.NotNil(t, pub, "row should surface from GetPublishedByID after re-publishing")

	// Unknown id for the correct user is a no-op
	updated, err = store.SetPublished(ctx, "erin", "unknown", true)
	require.ErrorIs(t, err, ErrSigningKeyNotFound)
	require.Nil(t, updated)
}

func TestSigningKeyStoreDelete(t *testing.T) {
	ctx := t.Context()
	conn := newTestDatabase(t)
	require.NoError(t, RunMigrations(ctx, conn, nil))

	authStore, err := NewAuthStore(conn)
	require.NoError(t, err)
	newSigningKeyTestUser(t, authStore, "owen")
	newSigningKeyTestUser(t, authStore, "peggy")

	store, err := NewSigningKeyStore(conn)
	require.NoError(t, err)
	_, err = store.Create(ctx, InsertSigningKeyInput{
		ID: "id-o", UserID: "owen", Algorithm: "ES256", KeyLabel: "k",
		JWK: `{}`, PEM: "pem", Published: true,
	})
	require.NoError(t, err)

	// Cross-user delete fails silently — row still there
	ok, err := store.Delete(ctx, "peggy", "id-o")
	require.NoError(t, err)
	require.False(t, ok)

	rec, err := store.GetByID(ctx, "id-o")
	require.NoError(t, err)
	require.NotNil(t, rec)

	// Owen deletes her own row
	ok, err = store.Delete(ctx, "owen", "id-o")
	require.NoError(t, err)
	require.True(t, ok)

	rec, err = store.GetByID(ctx, "id-o")
	require.NoError(t, err)
	require.Nil(t, rec, "Delete must hard-delete the row")

	// Second delete is a no-op
	ok, err = store.Delete(ctx, "owen", "id-o")
	require.NoError(t, err)
	require.False(t, ok)

	// After delete, a fresh Insert under the same (user, algorithm, label) must succeed
	inserted, err := store.Create(ctx, InsertSigningKeyInput{
		ID: "id-o2", UserID: "owen", Algorithm: "ES256", KeyLabel: "k",
		JWK: `{}`, PEM: "pem", Published: true,
	})
	require.NoError(t, err)
	require.NotNil(t, inserted, "Insert must succeed after Delete has cleared the previous row")
}

func TestSigningKeyStoreGetByIDNotFoundReturnsNil(t *testing.T) {
	ctx := t.Context()
	conn := newTestDatabase(t)
	require.NoError(t, RunMigrations(ctx, conn, nil))

	store, err := NewSigningKeyStore(conn)
	require.NoError(t, err)

	rec, err := store.GetByID(ctx, "unknown-id")
	require.NoError(t, err)
	require.Nil(t, rec)
}

func TestSigningKeyStoreCreateUnpublishedInsertsHidden(t *testing.T) {
	ctx := t.Context()
	conn := newTestDatabase(t)
	require.NoError(t, RunMigrations(ctx, conn, nil))

	authStore, err := NewAuthStore(conn)
	require.NoError(t, err)
	newSigningKeyTestUser(t, authStore, "frank")

	store, err := NewSigningKeyStore(conn)
	require.NoError(t, err)

	inserted, err := store.Create(ctx, InsertSigningKeyInput{
		ID:        "id-auto",
		UserID:    "frank",
		Algorithm: "ES256",
		KeyLabel:  "auto-label",
		JWK:       `{"kty":"EC","crv":"P-256","x":"X","y":"Y"}`,
		PEM:       "-----BEGIN PUBLIC KEY-----\nAAA\n-----END PUBLIC KEY-----",
		Published: false,
	})
	require.NoError(t, err)
	require.NotNil(t, inserted, "first Create call for a new (user, algorithm, label) must insert")
	require.False(t, inserted.Published, "returned row must report Published=false")

	rec, err := store.GetByID(ctx, "id-auto")
	require.NoError(t, err)
	require.NotNil(t, rec)
	require.Equal(t, "frank", rec.UserID)
	require.Equal(t, "ES256", rec.Algorithm)
	require.Equal(t, "auto-label", rec.KeyLabel)
	require.False(t, rec.Published, "rows created with Published=false must stay unpublished")
	require.Equal(t, rec.CreatedAt.Unix(), rec.UpdatedAt.Unix(), "created_at and updated_at must match on insert")

	// An unpublished row is not served from the published-only getter
	pub, err := store.GetPublishedByID(ctx, "id-auto")
	require.NoError(t, err)
	require.Nil(t, pub, "GetPublishedByID must hide unpublished rows until they are published")
}

func TestSigningKeyStoreCreateUnpublishedNoOpOnExisting(t *testing.T) {
	ctx := t.Context()
	conn := newTestDatabase(t)
	require.NoError(t, RunMigrations(ctx, conn, nil))

	authStore, err := NewAuthStore(conn)
	require.NoError(t, err)
	newSigningKeyTestUser(t, authStore, "gina")

	store, err := NewSigningKeyStore(conn)
	require.NoError(t, err)

	first := InsertSigningKeyInput{
		ID:        "id-first",
		UserID:    "gina",
		Algorithm: "ES256",
		KeyLabel:  "shared-label",
		JWK:       `{"first":true}`,
		PEM:       "first-pem",
		Published: false,
	}
	inserted, err := store.Create(ctx, first)
	require.NoError(t, err)
	require.NotNil(t, inserted)

	rec1, err := store.GetByID(ctx, "id-first")
	require.NoError(t, err)
	require.NotNil(t, rec1)
	updatedAt1 := rec1.UpdatedAt.Unix()

	// Sleep past the 1-second unix-time resolution so a missed update would be observable
	time.Sleep(1_100 * time.Millisecond)

	// A second Create with different material under the same (user, algorithm, label) must not overwrite the existing row
	inserted, err = store.Create(ctx, InsertSigningKeyInput{
		ID:        "id-second",
		UserID:    "gina",
		Algorithm: "ES256",
		KeyLabel:  "shared-label",
		JWK:       `{"second":true}`,
		PEM:       "second-pem",
		Published: false,
	})
	require.ErrorIs(t, err, ErrSigningKeyAlreadyExists, "Create on an existing (user, algorithm, label) row must report no insert")
	require.Nil(t, inserted)

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

func TestSigningKeyStoreCreateUnpublishedNoOpWhenPublished(t *testing.T) {
	ctx := t.Context()
	conn := newTestDatabase(t)
	require.NoError(t, RunMigrations(ctx, conn, nil))

	authStore, err := NewAuthStore(conn)
	require.NoError(t, err)
	newSigningKeyTestUser(t, authStore, "henry")

	store, err := NewSigningKeyStore(conn)
	require.NoError(t, err)

	// Publish a row first, then attempt to auto-store the same (user, algorithm, label) as unpublished
	_, err = store.Create(ctx, InsertSigningKeyInput{
		ID:        "id-pub",
		UserID:    "henry",
		Algorithm: "ES256",
		KeyLabel:  "keep-published",
		JWK:       `{"pub":true}`,
		PEM:       "pub-pem",
		Published: true,
	})
	require.NoError(t, err)

	inserted, err := store.Create(ctx, InsertSigningKeyInput{
		ID:        "id-auto",
		UserID:    "henry",
		Algorithm: "ES256",
		KeyLabel:  "keep-published",
		JWK:       `{"auto":true}`,
		PEM:       "auto-pem",
		Published: false,
	})
	require.ErrorIs(t, err, ErrSigningKeyAlreadyExists, "Create with Published=false must not touch a row that is already published")
	require.Nil(t, inserted)

	rec, err := store.GetByID(ctx, "id-pub")
	require.NoError(t, err)
	require.NotNil(t, rec)
	require.True(t, rec.Published, "published row must stay published")
	require.Equal(t, `{"pub":true}`, rec.JWK, "published material must not be overwritten")
}

func TestSigningKeyStoreCreateUnpublishedScopedPerUserAlgorithmLabel(t *testing.T) {
	ctx := t.Context()
	conn := newTestDatabase(t)
	require.NoError(t, RunMigrations(ctx, conn, nil))

	authStore, err := NewAuthStore(conn)
	require.NoError(t, err)
	newSigningKeyTestUser(t, authStore, "ivan")
	newSigningKeyTestUser(t, authStore, "judy")

	store, err := NewSigningKeyStore(conn)
	require.NoError(t, err)

	// Same (algorithm, label) for two different users must both insert — the unique index is (user_id, algorithm, key_label)
	insertedIvan, err := store.Create(ctx, InsertSigningKeyInput{
		ID: "id-ivan", UserID: "ivan", Algorithm: "ES256", KeyLabel: "shared",
		JWK: `{}`, PEM: "pem", Published: false,
	})
	require.NoError(t, err)
	require.NotNil(t, insertedIvan)

	insertedJudy, err := store.Create(ctx, InsertSigningKeyInput{
		ID: "id-judy", UserID: "judy", Algorithm: "ES256", KeyLabel: "shared",
		JWK: `{}`, PEM: "pem", Published: false,
	})
	require.NoError(t, err)
	require.NotNil(t, insertedJudy, "second user with the same algorithm+label must still get a row")

	// Same user with a different algorithm under the same label must also insert
	insertedES384, err := store.Create(ctx, InsertSigningKeyInput{
		ID: "id-ivan-es384", UserID: "ivan", Algorithm: "ES384", KeyLabel: "shared",
		JWK: `{}`, PEM: "pem", Published: false,
	})
	require.NoError(t, err)
	require.NotNil(t, insertedES384, "same user with a different algorithm must still get a row")
}

func TestSigningKeyStoreSetPublishedPromotesAutoStored(t *testing.T) {
	ctx := t.Context()
	conn := newTestDatabase(t)
	require.NoError(t, RunMigrations(ctx, conn, nil))

	authStore, err := NewAuthStore(conn)
	require.NoError(t, err)
	newSigningKeyTestUser(t, authStore, "kate")

	store, err := NewSigningKeyStore(conn)
	require.NoError(t, err)

	// Auto-store first (Published=false), then promote via SetPublished — Create alone can't promote under the new insert-only semantics
	inserted, err := store.Create(ctx, InsertSigningKeyInput{
		ID:        "id-k",
		UserID:    "kate",
		Algorithm: "ES256",
		KeyLabel:  "promoteme",
		JWK:       `{"x":1}`,
		PEM:       "pem",
		Published: false,
	})
	require.NoError(t, err)
	require.NotNil(t, inserted)

	rec, err := store.GetByID(ctx, "id-k")
	require.NoError(t, err)
	require.NotNil(t, rec)
	require.False(t, rec.Published)

	// GetPublishedByID must not surface an auto-stored row
	pub, err := store.GetPublishedByID(ctx, "id-k")
	require.NoError(t, err)
	require.Nil(t, pub)

	// Insert with the same (user, algorithm, label) is rejected — caller has to use SetPublished to promote the existing row
	inserted, err = store.Create(ctx, InsertSigningKeyInput{
		ID:        "id-k",
		UserID:    "kate",
		Algorithm: "ES256",
		KeyLabel:  "promoteme",
		JWK:       `{"x":1}`,
		PEM:       "pem",
		Published: true,
	})
	require.ErrorIs(t, err, ErrSigningKeyAlreadyExists, "Insert must not overwrite an existing auto-stored row under the same label")
	require.Nil(t, inserted)

	updated, err := store.SetPublished(ctx, "kate", "id-k", true)
	require.NoError(t, err)
	require.NotNil(t, updated)

	recAfter, err := store.GetByID(ctx, "id-k")
	require.NoError(t, err)
	require.NotNil(t, recAfter)
	require.True(t, recAfter.Published, "SetPublished must promote an auto-stored row to published=true")

	pubAfter, err := store.GetPublishedByID(ctx, "id-k")
	require.NoError(t, err)
	require.NotNil(t, pubAfter, "after SetPublished the row must be visible from GetPublishedByID")
}
