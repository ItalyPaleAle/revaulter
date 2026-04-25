package db

import (
	"context"
	"errors"
	"time"

	"github.com/italypaleale/go-sql-utils/adapter"
)

// PublishedSigningKey represents a public signing key known to the server
// The server never sees the corresponding private key: it is derived client-side from the user's primaryKey
type PublishedSigningKey struct {
	ID        string
	UserID    string
	Algorithm string
	KeyLabel  string
	JWK       string
	PEM       string
	Published bool
	CreatedAt time.Time
	UpdatedAt time.Time
}

type PublishedSigningKeyListItem struct {
	ID        string    `json:"id"`
	Algorithm string    `json:"algorithm"`
	KeyLabel  string    `json:"keyLabel"`
	Published bool      `json:"published"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

type InsertSigningKeyInput struct {
	ID        string
	UserID    string
	Algorithm string
	KeyLabel  string
	JWK       string
	PEM       string
	Published bool
}

var (
	// ErrSigningKeyAlreadyExists is returned by Create when a row already exists for the (user_id, algorithm, key_label) tuple
	ErrSigningKeyAlreadyExists = errors.New("a signing key already exists for this algorithm and keyLabel")
	// ErrSigningKeyNotFound is returned by SetPublished when no row matches the given (user_id, id)
	ErrSigningKeyNotFound = errors.New("signing key not found")
)

type SigningKeyStore struct {
	db adapter.Querier
}

func NewSigningKeyStore(db adapter.Querier) (*SigningKeyStore, error) {
	if db == nil {
		return nil, errors.New("db is nil")
	}

	return &SigningKeyStore{
		db: db,
	}, nil
}

// Create stores a new signing key for the given (user_id, algorithm, key_label) and returns the inserted row
func (s *SigningKeyStore) Create(ctx context.Context, in InsertSigningKeyInput) (*PublishedSigningKey, error) {
	now := time.Now().Unix()
	rec := &PublishedSigningKey{}
	var createdAt, updatedAt int64
	err := s.db.
		QueryRow(ctx,
			`INSERT INTO v2_published_signing_keys
				(id, user_id, algorithm, key_label, jwk, pem, published, created_at, updated_at)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $8)
				ON CONFLICT (user_id, algorithm, key_label) DO NOTHING
				RETURNING id, user_id, algorithm, key_label, jwk, pem, published, created_at, updated_at`,
			in.ID, in.UserID, in.Algorithm, in.KeyLabel, in.JWK, in.PEM, in.Published, now,
		).
		Scan(&rec.ID, &rec.UserID, &rec.Algorithm, &rec.KeyLabel, &rec.JWK, &rec.PEM, &rec.Published, &createdAt, &updatedAt)
	if s.db.IsNoRowsError(err) {
		return nil, ErrSigningKeyAlreadyExists
	} else if err != nil {
		return nil, err
	}

	rec.CreatedAt = time.Unix(createdAt, 0)
	rec.UpdatedAt = time.Unix(updatedAt, 0)

	return rec, nil
}

// AutoStoreUnpublished stores an unpublished signing key from the auto-store path that runs after a successful sign
// If a row already exists for (user_id, algorithm, key_label):
//   - and it is NOT published, the row is replaced with the new key (different thumbprint id, jwk, pem, updated_at); created_at is preserved
//   - and it IS published, the call is a no-op and ErrSigningKeyAlreadyExists is returned: a published key represents an explicit user decision and must not be silently demoted
//
// The replacement-while-unpublished semantics close a first-write-wins gap: a malicious script that submits an attacker-controlled JWK on the very first sign can no longer permanently claim the slot, because the next legitimate sign overwrites it. Once the user publishes a key the slot is locked
func (s *SigningKeyStore) AutoStoreUnpublished(ctx context.Context, in InsertSigningKeyInput) (*PublishedSigningKey, error) {
	if in.Published {
		// AutoStore must never write a published row; that's reserved for explicit user action via Create + SetPublished
		return nil, errors.New("auto-stored keys must not be marked published")
	}

	now := time.Now().Unix()
	rec := &PublishedSigningKey{}
	var createdAt, updatedAt int64
	err := s.db.
		QueryRow(ctx,
			`INSERT INTO v2_published_signing_keys
				(id, user_id, algorithm, key_label, jwk, pem, published, created_at, updated_at)
				VALUES ($1, $2, $3, $4, $5, $6, false, $7, $7)
				ON CONFLICT (user_id, algorithm, key_label) DO UPDATE
					SET id = EXCLUDED.id,
						jwk = EXCLUDED.jwk,
						pem = EXCLUDED.pem,
						updated_at = EXCLUDED.updated_at
					WHERE v2_published_signing_keys.published = false
				RETURNING id, user_id, algorithm, key_label, jwk, pem, published, created_at, updated_at`,
			in.ID, in.UserID, in.Algorithm, in.KeyLabel, in.JWK, in.PEM, now,
		).
		Scan(&rec.ID, &rec.UserID, &rec.Algorithm, &rec.KeyLabel, &rec.JWK, &rec.PEM, &rec.Published, &createdAt, &updatedAt)
	if s.db.IsNoRowsError(err) {
		// The conflict matched a published row, so the WHERE filter on the UPDATE skipped it
		return nil, ErrSigningKeyAlreadyExists
	} else if err != nil {
		return nil, err
	}

	rec.CreatedAt = time.Unix(createdAt, 0)
	rec.UpdatedAt = time.Unix(updatedAt, 0)

	return rec, nil
}

func (s *SigningKeyStore) GetByID(ctx context.Context, id string) (*PublishedSigningKey, error) {
	rec := &PublishedSigningKey{}
	var createdAt, updatedAt int64
	err := s.db.
		QueryRow(ctx,
			`SELECT id, user_id, algorithm, key_label, jwk, pem, published, created_at, updated_at
				FROM v2_published_signing_keys WHERE id = $1`,
			id,
		).
		Scan(&rec.ID, &rec.UserID, &rec.Algorithm, &rec.KeyLabel, &rec.JWK, &rec.PEM, &rec.Published, &createdAt, &updatedAt)
	if s.db.IsNoRowsError(err) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}

	rec.CreatedAt = time.Unix(createdAt, 0)
	rec.UpdatedAt = time.Unix(updatedAt, 0)

	return rec, nil
}

// GetPublishedByID returns a signing key only if it has been explicitly published
// This is what the public HTTP endpoint uses, so auto-stored keys are not served
func (s *SigningKeyStore) GetPublishedByID(ctx context.Context, id string) (*PublishedSigningKey, error) {
	rec, err := s.GetByID(ctx, id)
	if err != nil || rec == nil {
		return rec, err
	}
	if !rec.Published {
		return nil, nil
	}
	return rec, nil
}

// GetForUser returns a signing key owned by the given user regardless of whether it is published
// Returns nil if no matching row exists (unknown id or belongs to another user) so a guessed id can't probe another user's keys
func (s *SigningKeyStore) GetForUser(ctx context.Context, userID, id string) (*PublishedSigningKey, error) {
	rec, err := s.GetByID(ctx, id)
	if err != nil || rec == nil {
		return rec, err
	}
	if rec.UserID != userID {
		return nil, nil
	}
	return rec, nil
}

// ListForUser returns the user's known keys (metadata only, no JWK/PEM)
// Both published and auto-stored keys are returned; the UI uses the Published flag to distinguish them
func (s *SigningKeyStore) ListForUser(ctx context.Context, userID string) ([]PublishedSigningKeyListItem, error) {
	rows, err := s.db.Query(ctx,
		`SELECT id, algorithm, key_label, published, created_at, updated_at
			FROM v2_published_signing_keys WHERE user_id = $1
			ORDER BY algorithm ASC, key_label ASC`,
		userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []PublishedSigningKeyListItem
	for rows.Next() {
		var item PublishedSigningKeyListItem
		var createdAt, updatedAt int64
		err = rows.Scan(&item.ID, &item.Algorithm, &item.KeyLabel, &item.Published, &createdAt, &updatedAt)
		if err != nil {
			return nil, err
		}

		item.CreatedAt = time.Unix(createdAt, 0)
		item.UpdatedAt = time.Unix(updatedAt, 0)
		out = append(out, item)
	}

	return out, rows.Err()
}

// Delete removes a signing key row belonging to the given user
// Returns true if a row was removed, false if no matching row exists
func (s *SigningKeyStore) Delete(ctx context.Context, userID, id string) (bool, error) {
	affected, err := s.db.Exec(ctx,
		`DELETE FROM v2_published_signing_keys WHERE user_id = $1 AND id = $2`,
		userID, id,
	)
	if err != nil {
		return false, err
	}

	return affected > 0, nil
}

// SetPublished toggles the published flag on an existing signing key belonging to the given user and returns the updated row
func (s *SigningKeyStore) SetPublished(ctx context.Context, userID, id string, published bool) (*PublishedSigningKey, error) {
	now := time.Now().Unix()
	rec := &PublishedSigningKey{}
	var createdAt, updatedAt int64
	err := s.db.
		QueryRow(ctx,
			`UPDATE v2_published_signing_keys
				SET published = $1, updated_at = $2
				WHERE user_id = $3 AND id = $4
				RETURNING id, user_id, algorithm, key_label, jwk, pem, published, created_at, updated_at`,
			published, now, userID, id,
		).
		Scan(&rec.ID, &rec.UserID, &rec.Algorithm, &rec.KeyLabel, &rec.JWK, &rec.PEM, &rec.Published, &createdAt, &updatedAt)
	if s.db.IsNoRowsError(err) {
		return nil, ErrSigningKeyNotFound
	} else if err != nil {
		return nil, err
	}

	rec.CreatedAt = time.Unix(createdAt, 0)
	rec.UpdatedAt = time.Unix(updatedAt, 0)

	return rec, nil
}
