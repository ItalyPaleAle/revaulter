package db

import (
	"context"
	"errors"
	"log/slog"
	"time"
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

type UpsertPublishedSigningKeyInput struct {
	ID        string
	UserID    string
	Algorithm string
	KeyLabel  string
	JWK       string
	PEM       string
}

type StoreAutoDerivedSigningKeyInput struct {
	ID        string
	UserID    string
	Algorithm string
	KeyLabel  string
	JWK       string
	PEM       string
}

type SigningKeyStore struct {
	db  *DB
	log *slog.Logger
}

func NewSigningKeyStore(db *DB, logger *slog.Logger) (*SigningKeyStore, error) {
	if db == nil {
		return nil, errors.New("db is nil")
	}
	if logger == nil {
		logger = slog.Default()
	}

	return &SigningKeyStore{
		db:  db,
		log: logger,
	}, nil
}

// Upsert inserts or replaces a published signing key for the given (user_id, algorithm, key_label)
// Because derivation is deterministic, the id (JWK thumbprint SHA-256) is expected to be the same across re-publications of the same material
// Re-publishing different material under the same label replaces the previous row and marks it published
// Calling Upsert on a row that was previously auto-stored (published=false) promotes it to published
func (s *SigningKeyStore) Upsert(ctx context.Context, in UpsertPublishedSigningKeyInput) error {
	now := time.Now().Unix()
	_, err := s.db.Exec(ctx,
		`INSERT INTO v2_published_signing_keys
			(id, user_id, algorithm, key_label, jwk, pem, published, created_at, updated_at)
			VALUES ($1, $2, $3, $4, $5, $6, true, $7, $8)
			ON CONFLICT (user_id, algorithm, key_label) DO UPDATE SET
				id = excluded.id,
				jwk = excluded.jwk,
				pem = excluded.pem,
				published = true,
				updated_at = excluded.updated_at`,
		in.ID, in.UserID, in.Algorithm, in.KeyLabel, in.JWK, in.PEM, now, now,
	)
	return err
}

// StoreAutoDerivedIfMissing stores a signing key that was derived for a sign operation if no row yet exists for (user_id, algorithm, key_label)
// The record is created with published=false, so the key is known to the server but is not served from the public endpoint until the user explicitly publishes it
// Returns true if a new row was inserted; false if a row already existed (published or not)
func (s *SigningKeyStore) StoreAutoDerivedIfMissing(ctx context.Context, in StoreAutoDerivedSigningKeyInput) (bool, error) {
	now := time.Now().Unix()
	affected, err := s.db.Exec(ctx,
		`INSERT INTO v2_published_signing_keys
			(id, user_id, algorithm, key_label, jwk, pem, published, created_at, updated_at)
			VALUES ($1, $2, $3, $4, $5, $6, false, $7, $7)
			ON CONFLICT (user_id, algorithm, key_label) DO NOTHING`,
		in.ID, in.UserID, in.Algorithm, in.KeyLabel, in.JWK, in.PEM, now,
	)
	if err != nil {
		return false, err
	}
	return affected > 0, nil
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

// ListForUser returns the user's known keys (metadata only, no JWK/PEM) so the settings UI can render the list without transferring key material
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

// Delete removes a published signing key
// It is scoped to the user so an authenticated caller cannot unpublish another user's key even if they guess the id
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
