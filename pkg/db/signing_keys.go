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
	ID                          string
	UserID                      string
	Algorithm                   string
	KeyLabel                    string
	JWK                         string
	PEM                         string
	Published                   bool
	PublicationPayload          string
	PublicationSignatureEs384   string
	PublicationSignatureMldsa87 string
	CreatedAt                   time.Time
	UpdatedAt                   time.Time
}

// HasPublicationProof reports whether the row carries a stored anchor-signed publication proof
// A row only surfaces from the public fetch endpoint when this is true and Published is also true
func (k *PublishedSigningKey) HasPublicationProof() bool {
	return k.PublicationPayload != "" && k.PublicationSignatureEs384 != "" && k.PublicationSignatureMldsa87 != ""
}

type PublishedSigningKeyListItem struct {
	ID        string    `json:"id"`
	Algorithm string    `json:"algorithm"`
	KeyLabel  string    `json:"keyLabel"`
	Published bool      `json:"published"`
	HasProof  bool      `json:"hasProof"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

type InsertSigningKeyInput struct {
	ID                          string
	UserID                      string
	Algorithm                   string
	KeyLabel                    string
	JWK                         string
	PEM                         string
	Published                   bool
	PublicationPayload          string
	PublicationSignatureEs384   string
	PublicationSignatureMldsa87 string
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
// Callers may include a publication proof in InsertSigningKeyInput (Publication* fields)
// Empty proof fields are valid for Published=false rows ("unproven candidate") but rejected upstream for Published=true
func (s *SigningKeyStore) Create(ctx context.Context, in InsertSigningKeyInput) (*PublishedSigningKey, error) {
	now := time.Now().Unix()
	rec := &PublishedSigningKey{}
	var createdAt, updatedAt int64
	err := s.db.
		QueryRow(ctx,
			`INSERT INTO v2_published_signing_keys
				(id, user_id, algorithm, key_label, jwk, pem, published, publication_payload, publication_signature_es384, publication_signature_mldsa87, created_at, updated_at)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $11)
				ON CONFLICT (user_id, algorithm, key_label) DO NOTHING
				RETURNING id, user_id, algorithm, key_label, jwk, pem, published, publication_payload, publication_signature_es384, publication_signature_mldsa87, created_at, updated_at`,
			in.ID, in.UserID, in.Algorithm, in.KeyLabel, in.JWK, in.PEM, in.Published, in.PublicationPayload, in.PublicationSignatureEs384, in.PublicationSignatureMldsa87, now,
		).
		Scan(&rec.ID, &rec.UserID, &rec.Algorithm, &rec.KeyLabel, &rec.JWK, &rec.PEM, &rec.Published, &rec.PublicationPayload, &rec.PublicationSignatureEs384, &rec.PublicationSignatureMldsa87, &createdAt, &updatedAt)
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
//   - and it is unpublished AND has no stored publication proof, the row is replaced with the new key (different thumbprint id, jwk, pem, updated_at); created_at is preserved
//   - and it is published OR has a stored publication proof, the call is a no-op and ErrSigningKeyAlreadyExists is returned: a published or proven row represents an explicit user decision and must not be silently overwritten
//
// The replacement-while-unproven-and-unpublished semantics close a first-write-wins gap: a malicious script that submits an attacker-controlled JWK on the very first sign can no longer permanently claim the slot, because the next legitimate sign overwrites it. Once the user proves or publishes a key the slot is locked
func (s *SigningKeyStore) AutoStoreUnpublished(ctx context.Context, in InsertSigningKeyInput) (*PublishedSigningKey, error) {
	if in.Published {
		// AutoStore must never write a published row; that's reserved for explicit user action via Create + SetPublished
		return nil, errors.New("auto-stored keys must not be marked published")
	}

	if in.PublicationPayload != "" || in.PublicationSignatureEs384 != "" || in.PublicationSignatureMldsa87 != "" {
		// AutoStore never carries a proof; a proof is the result of an explicit user decision, never an automatic side-effect of a sign
		return nil, errors.New("auto-stored keys must not carry a publication proof")
	}

	now := time.Now().Unix()
	rec := &PublishedSigningKey{}
	var createdAt, updatedAt int64
	err := s.db.
		QueryRow(ctx,
			`INSERT INTO v2_published_signing_keys
				(id, user_id, algorithm, key_label, jwk, pem, published, publication_payload, publication_signature_es384, publication_signature_mldsa87, created_at, updated_at)
				VALUES ($1, $2, $3, $4, $5, $6, false, '', '', '', $7, $7)
				ON CONFLICT (user_id, algorithm, key_label) DO UPDATE
					SET id = EXCLUDED.id,
						jwk = EXCLUDED.jwk,
						pem = EXCLUDED.pem,
						updated_at = EXCLUDED.updated_at
					WHERE v2_published_signing_keys.published = false
						AND v2_published_signing_keys.publication_payload = ''
				RETURNING id, user_id, algorithm, key_label, jwk, pem, published, publication_payload, publication_signature_es384, publication_signature_mldsa87, created_at, updated_at`,
			in.ID, in.UserID, in.Algorithm, in.KeyLabel, in.JWK, in.PEM, now,
		).
		Scan(&rec.ID, &rec.UserID, &rec.Algorithm, &rec.KeyLabel, &rec.JWK, &rec.PEM, &rec.Published, &rec.PublicationPayload, &rec.PublicationSignatureEs384, &rec.PublicationSignatureMldsa87, &createdAt, &updatedAt)
	if s.db.IsNoRowsError(err) {
		// The conflict matched a row that is either published or has a stored proof, so the WHERE filter on the UPDATE skipped it
		return nil, ErrSigningKeyAlreadyExists
	} else if err != nil {
		return nil, err
	}

	rec.CreatedAt = time.Unix(createdAt, 0)
	rec.UpdatedAt = time.Unix(updatedAt, 0)

	return rec, nil
}

// GetByUserAndLabel returns the signing key for the given (userID, algorithm, keyLabel) tuple
// Returns nil if no matching row exists
func (s *SigningKeyStore) GetByUserAndLabel(ctx context.Context, userID, algorithm, keyLabel string) (*PublishedSigningKey, error) {
	rec := &PublishedSigningKey{}
	var createdAt, updatedAt int64
	err := s.db.
		QueryRow(ctx,
			`SELECT id, user_id, algorithm, key_label, jwk, pem, published, publication_payload, publication_signature_es384, publication_signature_mldsa87, created_at, updated_at
				FROM v2_published_signing_keys
				WHERE user_id = $1 AND algorithm = $2 AND key_label = $3`,
			userID, algorithm, keyLabel,
		).
		Scan(&rec.ID, &rec.UserID, &rec.Algorithm, &rec.KeyLabel, &rec.JWK, &rec.PEM, &rec.Published, &rec.PublicationPayload, &rec.PublicationSignatureEs384, &rec.PublicationSignatureMldsa87, &createdAt, &updatedAt)
	if s.db.IsNoRowsError(err) {
		return nil, nil
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
			`SELECT id, user_id, algorithm, key_label, jwk, pem, published, publication_payload, publication_signature_es384, publication_signature_mldsa87, created_at, updated_at
				FROM v2_published_signing_keys WHERE id = $1`,
			id,
		).
		Scan(&rec.ID, &rec.UserID, &rec.Algorithm, &rec.KeyLabel, &rec.JWK, &rec.PEM, &rec.Published, &rec.PublicationPayload, &rec.PublicationSignatureEs384, &rec.PublicationSignatureMldsa87, &createdAt, &updatedAt)
	if s.db.IsNoRowsError(err) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}

	rec.CreatedAt = time.Unix(createdAt, 0)
	rec.UpdatedAt = time.Unix(updatedAt, 0)

	return rec, nil
}

// GetPublishedByID returns a signing key only if it has been explicitly published AND carries a stored publication proof
// This is what the public HTTP endpoint uses, so auto-stored or unproven rows are not served
func (s *SigningKeyStore) GetPublishedByID(ctx context.Context, id string) (*PublishedSigningKey, error) {
	rec, err := s.GetByID(ctx, id)
	if err != nil || rec == nil {
		return rec, err
	}
	if !rec.Published || !rec.HasPublicationProof() {
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

// ListForUser returns the user's known keys (metadata only, no JWK/PEM/proof bytes)
// Both published and auto-stored keys are returned; the UI uses the Published and HasProof flags to distinguish them
func (s *SigningKeyStore) ListForUser(ctx context.Context, userID string) ([]PublishedSigningKeyListItem, error) {
	rows, err := s.db.Query(ctx,
		`SELECT id, algorithm, key_label, published,
				CASE WHEN publication_payload <> '' AND publication_signature_es384 <> '' AND publication_signature_mldsa87 <> '' THEN 1 ELSE 0 END AS has_proof,
				created_at, updated_at
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
		var hasProof int
		err = rows.Scan(&item.ID, &item.Algorithm, &item.KeyLabel, &item.Published, &hasProof, &createdAt, &updatedAt)
		if err != nil {
			return nil, err
		}

		item.HasProof = hasProof != 0
		item.CreatedAt = time.Unix(createdAt, 0)
		item.UpdatedAt = time.Unix(updatedAt, 0)
		out = append(out, item)
	}

	return out, rows.Err()
}

// Delete removes a signing key row belonging to the given user and returns the deleted row
// Returns ErrSigningKeyNotFound when no matching row exists
func (s *SigningKeyStore) Delete(ctx context.Context, userID, id string) (*PublishedSigningKey, error) {
	rec := &PublishedSigningKey{}
	var createdAt, updatedAt int64
	err := s.db.
		QueryRow(ctx,
			`DELETE FROM v2_published_signing_keys
				WHERE user_id = $1 AND id = $2
				RETURNING id, user_id, algorithm, key_label, jwk, pem, published, publication_payload, publication_signature_es384, publication_signature_mldsa87, created_at, updated_at`,
			userID, id,
		).
		Scan(&rec.ID, &rec.UserID, &rec.Algorithm, &rec.KeyLabel, &rec.JWK, &rec.PEM, &rec.Published, &rec.PublicationPayload, &rec.PublicationSignatureEs384, &rec.PublicationSignatureMldsa87, &createdAt, &updatedAt)
	if s.db.IsNoRowsError(err) {
		return nil, ErrSigningKeyNotFound
	} else if err != nil {
		return nil, err
	}

	rec.CreatedAt = time.Unix(createdAt, 0)
	rec.UpdatedAt = time.Unix(updatedAt, 0)

	return rec, nil
}

// SetPublished toggles the published flag on an existing signing key belonging to the given user and returns the updated row
// The stored publication proof (if any) is preserved unchanged: this method is a pure flag toggle
func (s *SigningKeyStore) SetPublished(ctx context.Context, userID, id string, published bool) (*PublishedSigningKey, error) {
	now := time.Now().Unix()
	rec := &PublishedSigningKey{}
	var createdAt, updatedAt int64
	err := s.db.
		QueryRow(ctx,
			`UPDATE v2_published_signing_keys
				SET published = $1, updated_at = $2
				WHERE user_id = $3 AND id = $4
				RETURNING id, user_id, algorithm, key_label, jwk, pem, published, publication_payload, publication_signature_es384, publication_signature_mldsa87, created_at, updated_at`,
			published, now, userID, id,
		).
		Scan(&rec.ID, &rec.UserID, &rec.Algorithm, &rec.KeyLabel, &rec.JWK, &rec.PEM, &rec.Published, &rec.PublicationPayload, &rec.PublicationSignatureEs384, &rec.PublicationSignatureMldsa87, &createdAt, &updatedAt)
	if s.db.IsNoRowsError(err) {
		return nil, ErrSigningKeyNotFound
	} else if err != nil {
		return nil, err
	}

	rec.CreatedAt = time.Unix(createdAt, 0)
	rec.UpdatedAt = time.Unix(updatedAt, 0)

	return rec, nil
}

// StorePublicationProof writes the anchor-signed publication proof onto an existing row and returns the updated record
// Used when an unproven row is being promoted to published: the route handler verifies the proof against the row's material, then calls this to persist the proof bytes
// The published flag is left untouched so callers can run StorePublicationProof + SetPublished within the same transaction without coupling the two operations at the SQL level
func (s *SigningKeyStore) StorePublicationProof(ctx context.Context, userID, id, payload, sigEs384, sigMldsa87 string) (*PublishedSigningKey, error) {
	if payload == "" || sigEs384 == "" || sigMldsa87 == "" {
		return nil, errors.New("publication proof fields must all be non-empty")
	}

	now := time.Now().Unix()
	rec := &PublishedSigningKey{}
	var createdAt, updatedAt int64
	err := s.db.
		QueryRow(ctx,
			`UPDATE v2_published_signing_keys
				SET publication_payload = $1,
					publication_signature_es384 = $2,
					publication_signature_mldsa87 = $3,
					updated_at = $4
				WHERE user_id = $5 AND id = $6
				RETURNING id, user_id, algorithm, key_label, jwk, pem, published, publication_payload, publication_signature_es384, publication_signature_mldsa87, created_at, updated_at`,
			payload, sigEs384, sigMldsa87, now, userID, id,
		).
		Scan(&rec.ID, &rec.UserID, &rec.Algorithm, &rec.KeyLabel, &rec.JWK, &rec.PEM, &rec.Published, &rec.PublicationPayload, &rec.PublicationSignatureEs384, &rec.PublicationSignatureMldsa87, &createdAt, &updatedAt)
	if s.db.IsNoRowsError(err) {
		return nil, ErrSigningKeyNotFound
	} else if err != nil {
		return nil, err
	}

	rec.CreatedAt = time.Unix(createdAt, 0)
	rec.UpdatedAt = time.Unix(updatedAt, 0)

	return rec, nil
}
