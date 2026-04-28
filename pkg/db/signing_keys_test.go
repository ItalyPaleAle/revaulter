package db

import (
	"context"
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
	conn := newTestDatabase(t)
	require.NoError(t, RunMigrations(t.Context(), conn, nil))

	_, _ = ExecuteInTransaction(t.Context(), conn, 30*time.Second, func(ctx context.Context, tx *DbTx) (any, error) {
		as := tx.AuthStore()
		sks := tx.SigningKeyStore()

		newSigningKeyTestUser(t, as, "alice")

		in := InsertSigningKeyInput{
			ID:        "id-1",
			UserID:    "alice",
			Algorithm: "ES256",
			KeyLabel:  "payments",
			JWK:       `{"kty":"EC","crv":"P-256","x":"X","y":"Y"}`,
			PEM:       "-----BEGIN PUBLIC KEY-----\nAAA\n-----END PUBLIC KEY-----",
			Published: true,
		}

		inserted, err := sks.Create(ctx, in)
		require.NoError(t, err)
		require.NotNil(t, inserted, "first insert for a new (user, algorithm, label) must return the inserted row")
		require.Equal(t, "ES256", inserted.Algorithm)
		require.Equal(t, "payments", inserted.KeyLabel)

		rec1, err := sks.GetByID(ctx, "id-1")
		require.NoError(t, err)
		require.NotNil(t, rec1)
		require.Equal(t, "ES256", rec1.Algorithm)
		require.Equal(t, "payments", rec1.KeyLabel)
		createdAt1 := rec1.CreatedAt
		updatedAt1 := rec1.UpdatedAt

		// Sleep past the 1-second unix-time resolution so a missed update would be observable on updated_at
		time.Sleep(1_100 * time.Millisecond)

		// A second insert for the same (user, algorithm, label) must fail with ErrSigningKeyAlreadyExists and leave the row untouched
		inserted, err = sks.Create(ctx, in)
		require.ErrorIs(t, err, ErrSigningKeyAlreadyExists, "duplicate insert must return ErrSigningKeyAlreadyExists")
		require.Nil(t, inserted)

		rec2, err := sks.GetByID(ctx, "id-1")
		require.NoError(t, err)
		require.NotNil(t, rec2)
		require.Equal(t, createdAt1.Unix(), rec2.CreatedAt.Unix(), "created_at must not change on duplicate insert")
		require.Equal(t, updatedAt1.Unix(), rec2.UpdatedAt.Unix(), "updated_at must not move on duplicate insert")

		return nil, nil
	})
}

func TestSigningKeyStoreInsertRejectsConflictingMaterial(t *testing.T) {
	conn := newTestDatabase(t)
	require.NoError(t, RunMigrations(t.Context(), conn, nil))

	_, _ = ExecuteInTransaction(t.Context(), conn, 30*time.Second, func(ctx context.Context, tx *DbTx) (any, error) {
		as := tx.AuthStore()
		sks := tx.SigningKeyStore()

		newSigningKeyTestUser(t, as, "bob")

		// Insert-only semantics: a second call with different material under the same (user, algorithm, label) must not overwrite the first row
		inserted, err := sks.Create(ctx, InsertSigningKeyInput{
			ID: "id-old", UserID: "bob", Algorithm: "ES256", KeyLabel: "main",
			JWK: `{"old":true}`, PEM: "old", Published: true,
		})
		require.NoError(t, err)
		require.NotNil(t, inserted)

		inserted, err = sks.Create(ctx, InsertSigningKeyInput{
			ID: "id-new", UserID: "bob", Algorithm: "ES256", KeyLabel: "main",
			JWK: `{"new":true}`, PEM: "new", Published: true,
		})
		require.ErrorIs(t, err, ErrSigningKeyAlreadyExists, "second insert with different material must be rejected")
		require.Nil(t, inserted)

		recOld, err := sks.GetByID(ctx, "id-old")
		require.NoError(t, err)
		require.NotNil(t, recOld, "original row must remain")
		require.Equal(t, `{"old":true}`, recOld.JWK)

		recNew, err := sks.GetByID(ctx, "id-new")
		require.NoError(t, err)
		require.Nil(t, recNew, "new material must not have been stored")

		return nil, nil
	})
}

func TestSigningKeyStoreListForUser(t *testing.T) {
	conn := newTestDatabase(t)
	require.NoError(t, RunMigrations(t.Context(), conn, nil))

	_, _ = ExecuteInTransaction(t.Context(), conn, 30*time.Second, func(ctx context.Context, tx *DbTx) (any, error) {
		as := tx.AuthStore()
		sks := tx.SigningKeyStore()

		newSigningKeyTestUser(t, as, "carol")
		newSigningKeyTestUser(t, as, "dave")

		_, err := sks.Create(ctx, InsertSigningKeyInput{
			ID: "id-c2", UserID: "carol", Algorithm: "ES256", KeyLabel: "zeta",
			JWK: `{}`, PEM: "pem", Published: true,
		})
		require.NoError(t, err)
		_, err = sks.Create(ctx, InsertSigningKeyInput{
			ID: "id-c1", UserID: "carol", Algorithm: "ES256", KeyLabel: "alpha",
			JWK: `{}`, PEM: "pem", Published: true,
		})
		require.NoError(t, err)
		_, err = sks.Create(ctx, InsertSigningKeyInput{
			ID: "id-d", UserID: "dave", Algorithm: "ES256", KeyLabel: "alpha",
			JWK: `{}`, PEM: "pem", Published: true,
		})
		require.NoError(t, err)

		items, err := sks.ListForUser(ctx, "carol")
		require.NoError(t, err)
		require.Len(t, items, 2)
		// Sorted by algorithm asc, key_label asc
		require.Equal(t, "alpha", items[0].KeyLabel)
		require.Equal(t, "zeta", items[1].KeyLabel)

		// Listing does not leak another user's records
		for _, item := range items {
			require.NotEqual(t, "id-d", item.ID)
		}

		empty, err := sks.ListForUser(ctx, "no-such-user")
		require.NoError(t, err)
		require.Empty(t, empty)

		return nil, nil
	})
}

func TestSigningKeyStoreSetPublished(t *testing.T) {
	conn := newTestDatabase(t)
	require.NoError(t, RunMigrations(t.Context(), conn, nil))

	_, _ = ExecuteInTransaction(t.Context(), conn, 30*time.Second, func(ctx context.Context, tx *DbTx) (any, error) {
		as := tx.AuthStore()
		sks := tx.SigningKeyStore()

		newSigningKeyTestUser(t, as, "erin")
		newSigningKeyTestUser(t, as, "mallory")

		// Create a proven published row so GetPublishedByID surfaces it after re-publishing
		_, err := sks.Create(ctx, InsertSigningKeyInput{
			ID: "id-e", UserID: "erin", Algorithm: "ES256", KeyLabel: "k",
			JWK: `{}`, PEM: "pem", Published: true,
			PublicationPayload:          "payload-bytes",
			PublicationSignatureEs384:   "es-sig",
			PublicationSignatureMldsa87: "ml-sig",
		})
		require.NoError(t, err)

		// Another user cannot flip erin's key even if they know the id
		updated, err := sks.SetPublished(ctx, "mallory", "id-e", false)
		require.ErrorIs(t, err, ErrSigningKeyNotFound)
		require.Nil(t, updated)

		rec, err := sks.GetByID(ctx, "id-e")
		require.NoError(t, err)
		require.NotNil(t, rec)
		require.True(t, rec.Published, "cross-user update must not flip the flag")

		// Sleep past the 1-second unix-time resolution so updated_at can visibly advance
		time.Sleep(1_100 * time.Millisecond)

		// Erin unpublishes her own key — the row stays but published becomes false
		updated, err = sks.SetPublished(ctx, "erin", "id-e", false)
		require.NoError(t, err)
		require.NotNil(t, updated, "SetPublished must return the updated row")
		require.False(t, updated.Published)
		require.Greater(t, updated.UpdatedAt.Unix(), updated.CreatedAt.Unix(), "updated_at must advance on SetPublished")

		rec, err = sks.GetByID(ctx, "id-e")
		require.NoError(t, err)
		require.NotNil(t, rec, "SetPublished must not delete the row")
		require.False(t, rec.Published)

		// Re-publishing the same row brings it back via the public endpoint
		updated, err = sks.SetPublished(ctx, "erin", "id-e", true)
		require.NoError(t, err)
		require.NotNil(t, updated)
		require.True(t, updated.Published)

		pub, err := sks.GetPublishedByID(ctx, "id-e")
		require.NoError(t, err)
		require.NotNil(t, pub, "row should surface from GetPublishedByID after re-publishing")

		// Unknown id for the correct user is a no-op
		updated, err = sks.SetPublished(ctx, "erin", "unknown", true)
		require.ErrorIs(t, err, ErrSigningKeyNotFound)
		require.Nil(t, updated)

		return nil, nil
	})
}

func TestSigningKeyStoreDelete(t *testing.T) {
	conn := newTestDatabase(t)
	require.NoError(t, RunMigrations(t.Context(), conn, nil))

	_, _ = ExecuteInTransaction(t.Context(), conn, 30*time.Second, func(ctx context.Context, tx *DbTx) (any, error) {
		as := tx.AuthStore()
		sks := tx.SigningKeyStore()

		newSigningKeyTestUser(t, as, "owen")
		newSigningKeyTestUser(t, as, "peggy")

		_, err := sks.Create(ctx, InsertSigningKeyInput{
			ID: "id-o", UserID: "owen", Algorithm: "ES256", KeyLabel: "k",
			JWK: `{}`, PEM: "pem", Published: true,
		})
		require.NoError(t, err)

		// Cross-user delete returns ErrSigningKeyNotFound — the row is unchanged
		deleted, err := sks.Delete(ctx, "peggy", "id-o")
		require.ErrorIs(t, err, ErrSigningKeyNotFound)
		require.Nil(t, deleted)

		rec, err := sks.GetByID(ctx, "id-o")
		require.NoError(t, err)
		require.NotNil(t, rec)

		// Owen deletes their own row — returned record carries the deleted row's content
		deleted, err = sks.Delete(ctx, "owen", "id-o")
		require.NoError(t, err)
		require.NotNil(t, deleted)
		require.Equal(t, "id-o", deleted.ID)
		require.Equal(t, "owen", deleted.UserID)
		require.Equal(t, "ES256", deleted.Algorithm)

		rec, err = sks.GetByID(ctx, "id-o")
		require.NoError(t, err)
		require.Nil(t, rec, "Delete must hard-delete the row")

		// Second delete returns ErrSigningKeyNotFound
		deleted, err = sks.Delete(ctx, "owen", "id-o")
		require.ErrorIs(t, err, ErrSigningKeyNotFound)
		require.Nil(t, deleted)

		// After delete, a fresh Insert under the same (user, algorithm, label) must succeed
		inserted, err := sks.Create(ctx, InsertSigningKeyInput{
			ID: "id-o2", UserID: "owen", Algorithm: "ES256", KeyLabel: "k",
			JWK: `{}`, PEM: "pem", Published: true,
		})
		require.NoError(t, err)
		require.NotNil(t, inserted, "Insert must succeed after Delete has cleared the previous row")

		return nil, nil
	})
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
	conn := newTestDatabase(t)
	require.NoError(t, RunMigrations(t.Context(), conn, nil))

	_, _ = ExecuteInTransaction(t.Context(), conn, 30*time.Second, func(ctx context.Context, tx *DbTx) (any, error) {
		as := tx.AuthStore()
		sks := tx.SigningKeyStore()

		newSigningKeyTestUser(t, as, "frank")

		inserted, err := sks.Create(ctx, InsertSigningKeyInput{
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

		rec, err := sks.GetByID(ctx, "id-auto")
		require.NoError(t, err)
		require.NotNil(t, rec)
		require.Equal(t, "frank", rec.UserID)
		require.Equal(t, "ES256", rec.Algorithm)
		require.Equal(t, "auto-label", rec.KeyLabel)
		require.False(t, rec.Published, "rows created with Published=false must stay unpublished")
		require.Equal(t, rec.CreatedAt.Unix(), rec.UpdatedAt.Unix(), "created_at and updated_at must match on insert")

		// An unpublished row is not served from the published-only getter
		pub, err := sks.GetPublishedByID(ctx, "id-auto")
		require.NoError(t, err)
		require.Nil(t, pub, "GetPublishedByID must hide unpublished rows until they are published")

		return nil, nil
	})
}

func TestSigningKeyStoreCreateUnpublishedNoOpOnExisting(t *testing.T) {
	conn := newTestDatabase(t)
	require.NoError(t, RunMigrations(t.Context(), conn, nil))

	_, _ = ExecuteInTransaction(t.Context(), conn, 30*time.Second, func(ctx context.Context, tx *DbTx) (any, error) {
		as := tx.AuthStore()
		sks := tx.SigningKeyStore()

		newSigningKeyTestUser(t, as, "gina")

		first := InsertSigningKeyInput{
			ID:        "id-first",
			UserID:    "gina",
			Algorithm: "ES256",
			KeyLabel:  "shared-label",
			JWK:       `{"first":true}`,
			PEM:       "first-pem",
			Published: false,
		}
		inserted, err := sks.Create(ctx, first)
		require.NoError(t, err)
		require.NotNil(t, inserted)

		rec1, err := sks.GetByID(ctx, "id-first")
		require.NoError(t, err)
		require.NotNil(t, rec1)
		updatedAt1 := rec1.UpdatedAt.Unix()

		// Sleep past the 1-second unix-time resolution so a missed update would be observable
		time.Sleep(1_100 * time.Millisecond)

		// A second Create with different material under the same (user, algorithm, label) must not overwrite the existing row
		inserted, err = sks.Create(ctx, InsertSigningKeyInput{
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
		recSecond, err := sks.GetByID(ctx, "id-second")
		require.NoError(t, err)
		require.Nil(t, recSecond)

		rec1Again, err := sks.GetByID(ctx, "id-first")
		require.NoError(t, err)
		require.NotNil(t, rec1Again)
		require.Equal(t, `{"first":true}`, rec1Again.JWK)
		require.Equal(t, "first-pem", rec1Again.PEM)
		require.False(t, rec1Again.Published)
		require.Equal(t, updatedAt1, rec1Again.UpdatedAt.Unix(), "updated_at must not move when the insert is skipped")

		return nil, nil
	})
}

func TestSigningKeyStoreCreateUnpublishedNoOpWhenPublished(t *testing.T) {
	conn := newTestDatabase(t)
	require.NoError(t, RunMigrations(t.Context(), conn, nil))

	_, _ = ExecuteInTransaction(t.Context(), conn, 30*time.Second, func(ctx context.Context, tx *DbTx) (any, error) {
		as := tx.AuthStore()
		sks := tx.SigningKeyStore()

		newSigningKeyTestUser(t, as, "henry")

		// Publish a row first, then attempt to auto-store the same (user, algorithm, label) as unpublished
		_, err := sks.Create(ctx, InsertSigningKeyInput{
			ID:        "id-pub",
			UserID:    "henry",
			Algorithm: "ES256",
			KeyLabel:  "keep-published",
			JWK:       `{"pub":true}`,
			PEM:       "pub-pem",
			Published: true,
		})
		require.NoError(t, err)

		inserted, err := sks.Create(ctx, InsertSigningKeyInput{
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

		rec, err := sks.GetByID(ctx, "id-pub")
		require.NoError(t, err)
		require.NotNil(t, rec)
		require.True(t, rec.Published, "published row must stay published")
		require.Equal(t, `{"pub":true}`, rec.JWK, "published material must not be overwritten")

		return nil, nil
	})
}

func TestSigningKeyStoreCreateUnpublishedScopedPerUserAlgorithmLabel(t *testing.T) {
	conn := newTestDatabase(t)
	require.NoError(t, RunMigrations(t.Context(), conn, nil))

	_, _ = ExecuteInTransaction(t.Context(), conn, 30*time.Second, func(ctx context.Context, tx *DbTx) (any, error) {
		as := tx.AuthStore()
		sks := tx.SigningKeyStore()

		newSigningKeyTestUser(t, as, "ivan")
		newSigningKeyTestUser(t, as, "judy")

		// Same (algorithm, label) for two different users must both insert — the unique index is (user_id, algorithm, key_label)
		insertedIvan, err := sks.Create(ctx, InsertSigningKeyInput{
			ID: "id-ivan", UserID: "ivan", Algorithm: "ES256", KeyLabel: "shared",
			JWK: `{}`, PEM: "pem", Published: false,
		})
		require.NoError(t, err)
		require.NotNil(t, insertedIvan)

		insertedJudy, err := sks.Create(ctx, InsertSigningKeyInput{
			ID: "id-judy", UserID: "judy", Algorithm: "ES256", KeyLabel: "shared",
			JWK: `{}`, PEM: "pem", Published: false,
		})
		require.NoError(t, err)
		require.NotNil(t, insertedJudy, "second user with the same algorithm+label must still get a row")

		// Same user with a different algorithm under the same label must also insert
		insertedES384, err := sks.Create(ctx, InsertSigningKeyInput{
			ID: "id-ivan-es384", UserID: "ivan", Algorithm: "ES384", KeyLabel: "shared",
			JWK: `{}`, PEM: "pem", Published: false,
		})
		require.NoError(t, err)
		require.NotNil(t, insertedES384, "same user with a different algorithm must still get a row")

		return nil, nil
	})
}

func TestSigningKeyStoreSetPublishedPromotesAutoStored(t *testing.T) {
	conn := newTestDatabase(t)
	require.NoError(t, RunMigrations(t.Context(), conn, nil))

	_, _ = ExecuteInTransaction(t.Context(), conn, 30*time.Second, func(ctx context.Context, tx *DbTx) (any, error) {
		as := tx.AuthStore()
		sks := tx.SigningKeyStore()

		newSigningKeyTestUser(t, as, "kate")

		// Auto-store first (Published=false), then promote via SetPublished — Create alone can't promote under the new insert-only semantics
		inserted, err := sks.Create(ctx, InsertSigningKeyInput{
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

		rec, err := sks.GetByID(ctx, "id-k")
		require.NoError(t, err)
		require.NotNil(t, rec)
		require.False(t, rec.Published)

		// GetPublishedByID must not surface an auto-stored row
		pub, err := sks.GetPublishedByID(ctx, "id-k")
		require.NoError(t, err)
		require.Nil(t, pub)

		// Insert with the same (user, algorithm, label) is rejected — caller has to use SetPublished to promote the existing row
		inserted, err = sks.Create(ctx, InsertSigningKeyInput{
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

		// Even with Published=true, GetPublishedByID must hide rows that lack a stored publication proof
		// Promoting an unproven row to public requires StorePublicationProof + SetPublished(true)
		updated, err := sks.SetPublished(ctx, "kate", "id-k", true)
		require.NoError(t, err)
		require.NotNil(t, updated)

		recAfter, err := sks.GetByID(ctx, "id-k")
		require.NoError(t, err)
		require.NotNil(t, recAfter)
		require.True(t, recAfter.Published, "SetPublished must flip the flag even on unproven rows")

		pubBeforeProof, err := sks.GetPublishedByID(ctx, "id-k")
		require.NoError(t, err)
		require.Nil(t, pubBeforeProof, "GetPublishedByID must hide a row that has no stored proof, even when Published=true")

		// After storing a publication proof, the row surfaces from GetPublishedByID
		_, err = sks.StorePublicationProof(ctx, "kate", "id-k", "payload-bytes", "es-sig", "ml-sig")
		require.NoError(t, err)

		pubAfter, err := sks.GetPublishedByID(ctx, "id-k")
		require.NoError(t, err)
		require.NotNil(t, pubAfter, "after StorePublicationProof + SetPublished the row must be visible from GetPublishedByID")
		require.True(t, pubAfter.HasPublicationProof())

		return nil, nil
	})
}

func TestSigningKeyStoreAutoStoreUnpublishedReplacesExistingUnpublished(t *testing.T) {
	conn := newTestDatabase(t)
	require.NoError(t, RunMigrations(t.Context(), conn, nil))

	_, _ = ExecuteInTransaction(t.Context(), conn, 30*time.Second, func(ctx context.Context, tx *DbTx) (any, error) {
		as := tx.AuthStore()
		sks := tx.SigningKeyStore()

		newSigningKeyTestUser(t, as, "lara")

		// Simulate the "first sign was hostile" scenario: a row lands under an attacker thumbprint, unpublished
		first, err := sks.AutoStoreUnpublished(ctx, InsertSigningKeyInput{
			ID:        "id-attacker",
			UserID:    "lara",
			Algorithm: "ES256",
			KeyLabel:  "shared-label",
			JWK:       `{"attacker":true}`,
			PEM:       "attacker-pem",
		})
		require.NoError(t, err)
		require.NotNil(t, first)
		require.Equal(t, "id-attacker", first.ID)
		createdAt := first.CreatedAt.Unix()

		// Sleep past the 1-second unix-time resolution so updated_at moves on the replace
		time.Sleep(1_100 * time.Millisecond)

		// A subsequent legitimate sign must replace the unpublished row with the legit thumbprint, jwk, and pem
		replaced, err := sks.AutoStoreUnpublished(ctx, InsertSigningKeyInput{
			ID:        "id-legit",
			UserID:    "lara",
			Algorithm: "ES256",
			KeyLabel:  "shared-label",
			JWK:       `{"legit":true}`,
			PEM:       "legit-pem",
		})
		require.NoError(t, err)
		require.NotNil(t, replaced)
		require.Equal(t, "id-legit", replaced.ID)
		require.Equal(t, `{"legit":true}`, replaced.JWK)
		require.Equal(t, "legit-pem", replaced.PEM)
		require.False(t, replaced.Published)

		// created_at must be preserved on replace; updated_at must move forward
		require.Equal(t, createdAt, replaced.CreatedAt.Unix(), "created_at must be preserved when replacing an unpublished row")
		require.Greater(t, replaced.UpdatedAt.Unix(), createdAt, "updated_at must move forward on replace")

		// The old attacker row must be gone — its id is no longer addressable
		old, err := sks.GetByID(ctx, "id-attacker")
		require.NoError(t, err)
		require.Nil(t, old, "the previous unpublished row must have been replaced, not duplicated")

		// The replacement is the row that is now indexable by its new id
		current, err := sks.GetByID(ctx, "id-legit")
		require.NoError(t, err)
		require.NotNil(t, current)
		require.Equal(t, `{"legit":true}`, current.JWK)

		return nil, nil
	})
}

func TestSigningKeyStoreAutoStoreUnpublishedLeavesPublishedAlone(t *testing.T) {
	conn := newTestDatabase(t)
	require.NoError(t, RunMigrations(t.Context(), conn, nil))

	_, _ = ExecuteInTransaction(t.Context(), conn, 30*time.Second, func(ctx context.Context, tx *DbTx) (any, error) {
		as := tx.AuthStore()
		sks := tx.SigningKeyStore()

		newSigningKeyTestUser(t, as, "mary")

		// Publish a row first
		_, err := sks.Create(ctx, InsertSigningKeyInput{
			ID:        "id-pub",
			UserID:    "mary",
			Algorithm: "ES256",
			KeyLabel:  "locked-label",
			JWK:       `{"pub":true}`,
			PEM:       "pub-pem",
			Published: true,
		})
		require.NoError(t, err)

		// AutoStoreUnpublished must not silently demote or replace a published row
		// It returns ErrSigningKeyAlreadyExists so the caller treats it as a no-op
		replaced, err := sks.AutoStoreUnpublished(ctx, InsertSigningKeyInput{
			ID:        "id-auto",
			UserID:    "mary",
			Algorithm: "ES256",
			KeyLabel:  "locked-label",
			JWK:       `{"auto":true}`,
			PEM:       "auto-pem",
		})
		require.ErrorIs(t, err, ErrSigningKeyAlreadyExists)
		require.Nil(t, replaced)

		rec, err := sks.GetByID(ctx, "id-pub")
		require.NoError(t, err)
		require.NotNil(t, rec)
		require.True(t, rec.Published, "published row must remain published")
		require.Equal(t, `{"pub":true}`, rec.JWK, "published material must not be overwritten by an auto-store")

		return nil, nil
	})
}

func TestSigningKeyStoreAutoStoreUnpublishedRejectsPublishedInput(t *testing.T) {
	conn := newTestDatabase(t)
	require.NoError(t, RunMigrations(t.Context(), conn, nil))

	_, _ = ExecuteInTransaction(t.Context(), conn, 30*time.Second, func(ctx context.Context, tx *DbTx) (any, error) {
		as := tx.AuthStore()
		sks := tx.SigningKeyStore()

		newSigningKeyTestUser(t, as, "nina")

		// Defense-in-depth: AutoStoreUnpublished must refuse callers that pass Published=true
		// Promotion to published is reserved for Create + SetPublished
		_, err := sks.AutoStoreUnpublished(ctx, InsertSigningKeyInput{
			ID:        "id",
			UserID:    "nina",
			Algorithm: "ES256",
			KeyLabel:  "lbl",
			JWK:       `{}`,
			PEM:       "pem",
			Published: true,
		})
		require.Error(t, err)

		return nil, nil
	})
}

func TestSigningKeyStoreAutoStoreUnpublishedRejectsProofInput(t *testing.T) {
	conn := newTestDatabase(t)
	require.NoError(t, RunMigrations(t.Context(), conn, nil))

	_, _ = ExecuteInTransaction(t.Context(), conn, 30*time.Second, func(ctx context.Context, tx *DbTx) (any, error) {
		as := tx.AuthStore()
		sks := tx.SigningKeyStore()

		newSigningKeyTestUser(t, as, "olive")

		// Defense-in-depth: an auto-store call must never carry a publication proof
		// Proofs are an explicit user decision, never a side-effect of a sign
		_, err := sks.AutoStoreUnpublished(ctx, InsertSigningKeyInput{
			ID:                          "id",
			UserID:                      "olive",
			Algorithm:                   "ES256",
			KeyLabel:                    "lbl",
			JWK:                         `{}`,
			PEM:                         "pem",
			PublicationPayload:          "payload",
			PublicationSignatureEs384:   "es",
			PublicationSignatureMldsa87: "ml",
		})
		require.Error(t, err)

		return nil, nil
	})
}

func TestSigningKeyStoreAutoStoreUnpublishedLeavesProvenUnpublishedAlone(t *testing.T) {
	conn := newTestDatabase(t)
	require.NoError(t, RunMigrations(t.Context(), conn, nil))

	_, _ = ExecuteInTransaction(t.Context(), conn, 30*time.Second, func(ctx context.Context, tx *DbTx) (any, error) {
		as := tx.AuthStore()
		sks := tx.SigningKeyStore()

		newSigningKeyTestUser(t, as, "petra")

		// First the user creates a proven but unpublished row (Create with proof, Published=false)
		_, err := sks.Create(ctx, InsertSigningKeyInput{
			ID:                          "id-proven",
			UserID:                      "petra",
			Algorithm:                   "ES256",
			KeyLabel:                    "locked-by-proof",
			JWK:                         `{"proven":true}`,
			PEM:                         "proven-pem",
			Published:                   false,
			PublicationPayload:          "payload-bytes",
			PublicationSignatureEs384:   "es-sig",
			PublicationSignatureMldsa87: "ml-sig",
		})
		require.NoError(t, err)

		// AutoStoreUnpublished must skip the slot because the existing row carries a proof, even though Published=false
		replaced, err := sks.AutoStoreUnpublished(ctx, InsertSigningKeyInput{
			ID:        "id-attacker",
			UserID:    "petra",
			Algorithm: "ES256",
			KeyLabel:  "locked-by-proof",
			JWK:       `{"attacker":true}`,
			PEM:       "attacker-pem",
		})
		require.ErrorIs(t, err, ErrSigningKeyAlreadyExists)
		require.Nil(t, replaced)

		rec, err := sks.GetByID(ctx, "id-proven")
		require.NoError(t, err)
		require.NotNil(t, rec)
		require.Equal(t, `{"proven":true}`, rec.JWK, "proven material must not be overwritten by an auto-store")
		require.True(t, rec.HasPublicationProof())

		return nil, nil
	})
}

func TestSigningKeyStoreStorePublicationProofAddsProof(t *testing.T) {
	conn := newTestDatabase(t)
	require.NoError(t, RunMigrations(t.Context(), conn, nil))

	_, _ = ExecuteInTransaction(t.Context(), conn, 30*time.Second, func(ctx context.Context, tx *DbTx) (any, error) {
		as := tx.AuthStore()
		sks := tx.SigningKeyStore()

		newSigningKeyTestUser(t, as, "quinn")

		_, err := sks.Create(ctx, InsertSigningKeyInput{
			ID:        "id-q",
			UserID:    "quinn",
			Algorithm: "ES256",
			KeyLabel:  "k",
			JWK:       `{}`,
			PEM:       "pem",
			Published: false,
		})
		require.NoError(t, err)

		// Without proof, GetPublishedByID must hide the row even after SetPublished(true)
		_, err = sks.SetPublished(ctx, "quinn", "id-q", true)
		require.NoError(t, err)
		pub, err := sks.GetPublishedByID(ctx, "id-q")
		require.NoError(t, err)
		require.Nil(t, pub)

		// Adding the proof flips the row to publicly fetchable
		updated, err := sks.StorePublicationProof(ctx, "quinn", "id-q", "payload", "es-sig", "ml-sig")
		require.NoError(t, err)
		require.NotNil(t, updated)
		require.True(t, updated.HasPublicationProof())

		pub, err = sks.GetPublishedByID(ctx, "id-q")
		require.NoError(t, err)
		require.NotNil(t, pub)
		require.Equal(t, "payload", pub.PublicationPayload)

		// Cross-user updates are rejected
		_, err = sks.StorePublicationProof(ctx, "stranger", "id-q", "p", "e", "m")
		require.ErrorIs(t, err, ErrSigningKeyNotFound)

		// Empty proof fields are rejected (defense-in-depth)
		_, err = sks.StorePublicationProof(ctx, "quinn", "id-q", "", "e", "m")
		require.Error(t, err)

		return nil, nil
	})
}

func TestSigningKeyStoreSetPublishedPreservesProof(t *testing.T) {
	conn := newTestDatabase(t)
	require.NoError(t, RunMigrations(t.Context(), conn, nil))

	_, _ = ExecuteInTransaction(t.Context(), conn, 30*time.Second, func(ctx context.Context, tx *DbTx) (any, error) {
		as := tx.AuthStore()
		sks := tx.SigningKeyStore()

		newSigningKeyTestUser(t, as, "ruth")

		// Create a proven published row, then unpublish + re-publish; the proof must round-trip unchanged
		_, err := sks.Create(ctx, InsertSigningKeyInput{
			ID:                          "id-r",
			UserID:                      "ruth",
			Algorithm:                   "ES256",
			KeyLabel:                    "k",
			JWK:                         `{}`,
			PEM:                         "pem",
			Published:                   true,
			PublicationPayload:          "payload-bytes",
			PublicationSignatureEs384:   "es-sig",
			PublicationSignatureMldsa87: "ml-sig",
		})
		require.NoError(t, err)

		_, err = sks.SetPublished(ctx, "ruth", "id-r", false)
		require.NoError(t, err)

		rec, err := sks.GetByID(ctx, "id-r")
		require.NoError(t, err)
		require.NotNil(t, rec)
		require.Equal(t, "payload-bytes", rec.PublicationPayload, "SetPublished must preserve the stored proof")
		require.False(t, rec.Published)

		_, err = sks.SetPublished(ctx, "ruth", "id-r", true)
		require.NoError(t, err)

		recAfter, err := sks.GetByID(ctx, "id-r")
		require.NoError(t, err)
		require.NotNil(t, recAfter)
		require.Equal(t, "payload-bytes", recAfter.PublicationPayload)
		require.True(t, recAfter.Published)

		return nil, nil
	})
}

func TestSigningKeyStoreListForUserExposesProofFlag(t *testing.T) {
	conn := newTestDatabase(t)
	require.NoError(t, RunMigrations(t.Context(), conn, nil))

	_, _ = ExecuteInTransaction(t.Context(), conn, 30*time.Second, func(ctx context.Context, tx *DbTx) (any, error) {
		as := tx.AuthStore()
		sks := tx.SigningKeyStore()

		newSigningKeyTestUser(t, as, "sam")

		// Auto-stored row, no proof
		_, err := sks.AutoStoreUnpublished(ctx, InsertSigningKeyInput{
			ID: "id-1", UserID: "sam", Algorithm: "ES256", KeyLabel: "auto",
			JWK: `{}`, PEM: "pem",
		})
		require.NoError(t, err)

		// User-created row with proof
		_, err = sks.Create(ctx, InsertSigningKeyInput{
			ID: "id-2", UserID: "sam", Algorithm: "ES256", KeyLabel: "proven",
			JWK: `{}`, PEM: "pem", Published: true,
			PublicationPayload:          "payload",
			PublicationSignatureEs384:   "es",
			PublicationSignatureMldsa87: "ml",
		})
		require.NoError(t, err)

		items, err := sks.ListForUser(ctx, "sam")
		require.NoError(t, err)
		require.Len(t, items, 2)

		var auto, proven PublishedSigningKeyListItem
		for _, item := range items {
			switch item.KeyLabel {
			case "auto":
				auto = item
			case "proven":
				proven = item
			}
		}
		require.False(t, auto.HasProof, "auto-stored row must list HasProof=false")
		require.True(t, proven.HasProof, "proven row must list HasProof=true")

		return nil, nil
	})
}
