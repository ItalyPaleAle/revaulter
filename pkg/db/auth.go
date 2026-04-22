package db

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/italypaleale/go-sql-utils/adapter"
	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5/pgconn"
	"modernc.org/sqlite"

	"github.com/italypaleale/revaulter/pkg/utils"
)

type AuthStore struct {
	db adapter.DatabaseConn
}

type User struct {
	ID                           string
	DisplayName                  string
	Status                       string
	WebAuthnUserID               string
	RequestKey                   string
	RequestEncEcdhPubkey         string
	RequestEncMlkemPubkey        string
	AnchorEs384PublicKey         string
	AnchorMldsa87PublicKey       string
	PubkeyBundleSignatureEs384   string
	PubkeyBundleSignatureMldsa87 string
	WrappedKeyEpoch              int64
	AllowedIPs                   []string
	Ready                        bool
}

type AuthChallenge struct {
	ID        string
	Kind      string
	UserID    string
	Challenge string
	ExpiresAt time.Time
}

type AuthCredentialRecord struct {
	ID                          string
	CredentialID                string
	DisplayName                 string
	PublicKey                   string
	SignCount                   int64
	WrappedPrimaryKey           string
	WrappedAnchorKey            string
	AttestationPayload          string
	AttestationSignatureEs384   string
	AttestationSignatureMldsa87 string
	WrappedKeyEpoch             int64
	CreatedAt                   int64
	LastUsedAt                  int64
}

type RegisterUserInput struct {
	UserID                string
	DisplayName           string
	WebAuthnUserID        string
	CredentialID          string
	CredentialDisplayName string
	PublicKey             string
	SignCount             int64
	SessionTTL            time.Duration
}

type AddCredentialInput struct {
	UserID                      string
	CredentialID                string
	DisplayName                 string
	PublicKey                   string
	SignCount                   int64
	WrappedPrimaryKey           string
	WrappedAnchorKey            string
	AttestationPayload          string
	AttestationSignatureEs384   string
	AttestationSignatureMldsa87 string
}

type LoginInput struct {
	UserID       string
	CredentialID string
	SignCount    int64
	SessionTTL   time.Duration
}

type FinalizeSignupInput struct {
	UserID                       string
	WrappedPrimaryKey            string
	WrappedAnchorKey             string
	RequestEncEcdhPubkey         string
	RequestEncMlkemPubkey        string
	AnchorEs384PublicKey         string
	AnchorMldsa87PublicKey       string
	PubkeyBundleSignatureEs384   string
	PubkeyBundleSignatureMldsa87 string
	AttestationPayload           string
	AttestationSignatureEs384    string
	AttestationSignatureMldsa87  string
}

var (
	ErrUserAlreadyExists  = errors.New("user already exists")
	ErrUserNotFound       = errors.New("user not found")
	ErrInvalidLogin       = errors.New("invalid login")
	ErrPasswordAlreadySet = errors.New("password already set")
	ErrCredentialNotFound = errors.New("credential not found")
	ErrLastCredential     = errors.New("cannot delete the last credential")
	ErrDisplayNameTooLong = errors.New("display name is too long")
	ErrAlreadyFinalized   = errors.New("user is already finalized")
)

func NewAuthStore(db adapter.DatabaseConn) (*AuthStore, error) {
	if db == nil {
		return nil, errors.New("db is nil")
	}

	return &AuthStore{
		db: db,
	}, nil
}

func (s *AuthStore) CountUsers(ctx context.Context) (int, error) {
	var n int
	err := s.db.
		QueryRow(ctx, `SELECT COUNT(*) FROM v2_users`).
		Scan(&n)
	return n, err
}

func (s *AuthStore) GetUserByID(ctx context.Context, userID string) (*User, error) {
	return s.getUser(ctx, "id", userID)
}

func (s *AuthStore) GetUserByWebAuthnUserID(ctx context.Context, webAuthnUserID string) (*User, error) {
	return s.getUser(ctx, "webauthn_user_id", webAuthnUserID)
}

func (s *AuthStore) GetUserByRequestKey(ctx context.Context, requestKey string) (*User, error) {
	return s.getUser(ctx, "request_key", requestKey)
}

func (s *AuthStore) getUser(ctx context.Context, column string, value string) (*User, error) {
	switch column {
	case "id", "webauthn_user_id", "request_key":
		// All good
	default:
		return nil, fmt.Errorf("invalid column requested: %s", column)
	}

	var (
		user          User
		allowedIPsCSV string
	)
	query := `SELECT id, display_name, status, webauthn_user_id, request_key, request_enc_ecdh_pubkey, request_enc_mlkem_pubkey, anchor_es384_public_key, anchor_mldsa87_public_key, pubkey_bundle_signature_es384, pubkey_bundle_signature_mldsa87, wrapped_key_epoch, allowed_ips, ready
		FROM v2_users
		WHERE ` + column + ` = $1`
	err := s.db.
		QueryRow(ctx, query, value).
		Scan(&user.ID, &user.DisplayName, &user.Status, &user.WebAuthnUserID, &user.RequestKey, &user.RequestEncEcdhPubkey, &user.RequestEncMlkemPubkey, &user.AnchorEs384PublicKey, &user.AnchorMldsa87PublicKey, &user.PubkeyBundleSignatureEs384, &user.PubkeyBundleSignatureMldsa87, &user.WrappedKeyEpoch, &allowedIPsCSV, &user.Ready)
	if s.db.IsNoRowsError(err) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}

	user.AllowedIPs = parseAllowedIPsCSV(allowedIPsCSV)
	return &user, nil
}

func (s *AuthStore) ListCredentials(ctx context.Context, userID string) ([]AuthCredentialRecord, error) {
	rows, err := s.db.Query(ctx,
		`SELECT id, credential_id, display_name, public_key, sign_count, wrapped_primary_key, wrapped_anchor_key, attestation_payload, attestation_signature_es384, attestation_signature_mldsa87, wrapped_key_epoch, created_at, last_used_at
			FROM v2_user_credentials
			WHERE user_id = $1
			ORDER BY created_at ASC`,
		userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []AuthCredentialRecord
	for rows.Next() {
		var rec AuthCredentialRecord
		err = rows.Scan(&rec.ID, &rec.CredentialID, &rec.DisplayName, &rec.PublicKey, &rec.SignCount, &rec.WrappedPrimaryKey, &rec.WrappedAnchorKey, &rec.AttestationPayload, &rec.AttestationSignatureEs384, &rec.AttestationSignatureMldsa87, &rec.WrappedKeyEpoch, &rec.CreatedAt, &rec.LastUsedAt)
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}

	err = rows.Err()
	if err != nil {
		return nil, err
	}

	return out, nil
}

func (s *AuthStore) BeginChallenge(ctx context.Context, kind, userID string, ttl time.Duration) (*AuthChallenge, error) {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	rawChallenge := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, rawChallenge)
	if err != nil {
		return nil, err
	}

	rec := &AuthChallenge{
		ID:        uuid.NewString(),
		Kind:      kind,
		UserID:    userID,
		Challenge: base64.RawURLEncoding.EncodeToString(rawChallenge),
		ExpiresAt: time.Now().UTC().Add(ttl),
	}
	return rec, s.insertChallenge(ctx, rec, nil)
}

func (s *AuthStore) BeginChallengeWithPayload(ctx context.Context, kind, userID string, challenge string, expiresAt time.Time, payload any) (*AuthChallenge, error) {
	if challenge == "" {
		return nil, errors.New("challenge is empty")
	}
	if expiresAt.IsZero() {
		expiresAt = time.Now().UTC().Add(5 * time.Minute)
	}

	rec := &AuthChallenge{
		ID:        uuid.NewString(),
		Kind:      kind,
		UserID:    userID,
		Challenge: challenge,
		ExpiresAt: expiresAt,
	}

	var payloadBytes []byte
	if payload != nil {
		var err error
		payloadBytes, err = json.Marshal(payload)
		if err != nil {
			return nil, err
		}
	}
	return rec, s.insertChallenge(ctx, rec, payloadBytes)
}

func (s *AuthStore) insertChallenge(ctx context.Context, rec *AuthChallenge, payload []byte) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() {
		rollbackErr := tx.Rollback(ctx)
		if rollbackErr != nil && !s.db.IsTxDoneError(rollbackErr) {
			slog.Warn("Error rolling back transaction", slog.Any("err", rollbackErr))
		}
	}()

	_, err = tx.Exec(ctx,
		`INSERT INTO v2_auth_challenges (id, kind, user_id, challenge, expires_at) VALUES ($1, $2, $3, $4, $5)`,
		rec.ID, rec.Kind, rec.UserID, rec.Challenge, rec.ExpiresAt.Unix(),
	)
	if err != nil {
		return err
	}

	if len(payload) > 0 {
		_, err = tx.Exec(ctx,
			`INSERT INTO v2_auth_challenge_payloads (challenge_id, session_data) VALUES ($1, $2)`,
			rec.ID, string(payload),
		)
		if err != nil {
			return err
		}
	}

	err = tx.Commit(ctx)
	if err != nil {
		return err
	}

	return nil
}

func (s *AuthStore) ConsumeChallenge(ctx context.Context, id, kind string) (bool, error) {
	now := time.Now().Unix()
	affected, err := s.db.Exec(ctx,
		`UPDATE v2_auth_challenges SET used_at = $1 WHERE id = $2 AND kind = $3 AND used_at IS NULL AND expires_at >= $1`,
		now, id, kind,
	)
	if err != nil {
		return false, err
	}
	return affected == 1, nil
}

func (s *AuthStore) ConsumeChallengePayload(ctx context.Context, id, kind string, out any) (bool, error) {
	ok, err := s.ConsumeChallenge(ctx, id, kind)
	if err != nil || !ok {
		return ok, err
	}
	if out == nil {
		return true, nil
	}

	var payload string
	err = s.db.
		QueryRow(ctx, `SELECT session_data FROM v2_auth_challenge_payloads WHERE challenge_id = $1`, id).
		Scan(&payload)
	if s.db.IsNoRowsError(err) {
		return true, nil
	} else if err != nil {
		return false, err
	}

	err = json.Unmarshal([]byte(payload), out)
	if err != nil {
		return false, err
	}
	return true, nil
}

func (s *AuthStore) RegisterUser(ctx context.Context, in RegisterUserInput) (*User, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() {
		rollbackErr := tx.Rollback(ctx)
		if rollbackErr != nil && !s.db.IsTxDoneError(rollbackErr) {
			slog.Warn("Error rolling back transaction", slog.Any("err", rollbackErr))
		}
	}()

	requestKey, err := utils.RandomString(20)
	if err != nil {
		return nil, err
	}

	now := time.Now().Unix()
	_, err = tx.Exec(ctx,
		`INSERT INTO v2_users (id, display_name, status, webauthn_user_id, request_key, wrapped_key_epoch, allowed_ips, ready, created_at, updated_at)
			VALUES ($1, $2, 'active', $3, $4, 1, '', false, $5, $5)`,
		in.UserID, strings.TrimSpace(in.DisplayName), in.WebAuthnUserID, requestKey, now,
	)
	if isIntegrityViolationError(err) {
		return nil, ErrUserAlreadyExists
	} else if err != nil {
		return nil, err
	}

	_, err = tx.Exec(ctx,
		`INSERT INTO v2_user_credentials (id, user_id, credential_id, display_name, public_key, sign_count, created_at, last_used_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $7)`,
		uuid.NewString(), in.UserID, in.CredentialID, strings.TrimSpace(in.CredentialDisplayName), in.PublicKey, in.SignCount, now,
	)
	if isIntegrityViolationError(err) {
		return nil, ErrUserAlreadyExists
	} else if err != nil {
		return nil, err
	}

	err = tx.Commit(ctx)
	if err != nil {
		return nil, err
	}

	return &User{
		ID:              in.UserID,
		DisplayName:     strings.TrimSpace(in.DisplayName),
		Status:          "active",
		WebAuthnUserID:  in.WebAuthnUserID,
		RequestKey:      requestKey,
		WrappedKeyEpoch: 1,
		AllowedIPs:      nil,
		Ready:           false,
	}, nil
}

func (s *AuthStore) Login(ctx context.Context, in LoginInput) (*User, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() {
		rollbackErr := tx.Rollback(ctx)
		if rollbackErr != nil && !s.db.IsTxDoneError(rollbackErr) {
			slog.Warn("Error rolling back transaction", slog.Any("err", rollbackErr))
		}
	}()

	now := time.Now().Unix()
	err = tx.
		QueryRow(ctx,
			`UPDATE v2_user_credentials
			SET sign_count = $1, last_used_at = $2
			WHERE credential_id = $3
			AND user_id = (
				SELECT id FROM v2_users WHERE id = $4 AND status = 'active'
			)
			RETURNING user_id`,
			in.SignCount, now, in.CredentialID, in.UserID,
		).
		Scan(&in.UserID)
	if s.db.IsNoRowsError(err) {
		return nil, ErrInvalidLogin
	} else if err != nil {
		return nil, err
	}

	user := &User{}
	var allowedIPsCSV string
	err = tx.
		QueryRow(ctx,
			`SELECT id, display_name, status, webauthn_user_id, request_key, request_enc_ecdh_pubkey, request_enc_mlkem_pubkey, anchor_es384_public_key, anchor_mldsa87_public_key, pubkey_bundle_signature_es384, pubkey_bundle_signature_mldsa87, wrapped_key_epoch, allowed_ips, ready
			FROM v2_users
			WHERE id = $1 AND status = 'active'`,
			in.UserID,
		).
		Scan(
			&user.ID,
			&user.DisplayName,
			&user.Status,
			&user.WebAuthnUserID,
			&user.RequestKey,
			&user.RequestEncEcdhPubkey,
			&user.RequestEncMlkemPubkey,
			&user.AnchorEs384PublicKey,
			&user.AnchorMldsa87PublicKey,
			&user.PubkeyBundleSignatureEs384,
			&user.PubkeyBundleSignatureMldsa87,
			&user.WrappedKeyEpoch,
			&allowedIPsCSV,
			&user.Ready,
		)
	if s.db.IsNoRowsError(err) {
		return nil, ErrInvalidLogin
	} else if err != nil {
		return nil, err
	}

	user.AllowedIPs = parseAllowedIPsCSV(allowedIPsCSV)

	err = tx.Commit(ctx)
	if err != nil {
		return nil, err
	}

	return user, nil
}

// FinalizeSignup marks the account as ready and persists all long-lived cryptographic material generated at signup time: the user's transport pubkeys, anchor pubkeys and bundle self-signatures, plus the first credential's wrapped primary key, wrapped anchor key, and hybrid attestation
// Returns the updated user row
func (s *AuthStore) FinalizeSignup(ctx context.Context, in FinalizeSignupInput) (*User, error) {
	if len(in.WrappedPrimaryKey) > 512 {
		return nil, errors.New("wrappedPrimaryKey is too large")
	}
	if len(in.WrappedAnchorKey) > 32768 {
		return nil, errors.New("wrappedAnchorKey is too large")
	}
	if len(in.AttestationPayload) > 4096 {
		return nil, errors.New("attestationPayload is too large")
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() {
		rollbackErr := tx.Rollback(ctx)
		if rollbackErr != nil && !s.db.IsTxDoneError(rollbackErr) {
			slog.Warn("Error rolling back transaction", slog.Any("err", rollbackErr))
		}
	}()

	now := time.Now().Unix()
	updatedUser := &User{}
	var allowedIPsCSV string
	err = tx.
		QueryRow(ctx,
			`UPDATE v2_users
			SET request_enc_ecdh_pubkey = $1,
				request_enc_mlkem_pubkey = $2,
				anchor_es384_public_key = $3,
				anchor_mldsa87_public_key = $4,
				pubkey_bundle_signature_es384 = $5,
				pubkey_bundle_signature_mldsa87 = $6,
				ready = true,
				updated_at = $7
			WHERE id = $8 AND ready = false
			RETURNING
				id, display_name, status, webauthn_user_id, request_key, request_enc_ecdh_pubkey, request_enc_mlkem_pubkey, anchor_es384_public_key, anchor_mldsa87_public_key, pubkey_bundle_signature_es384, pubkey_bundle_signature_mldsa87, wrapped_key_epoch, allowed_ips, ready`,
			in.RequestEncEcdhPubkey, in.RequestEncMlkemPubkey,
			in.AnchorEs384PublicKey, in.AnchorMldsa87PublicKey,
			in.PubkeyBundleSignatureEs384, in.PubkeyBundleSignatureMldsa87,
			now, in.UserID,
		).
		Scan(
			&updatedUser.ID,
			&updatedUser.DisplayName,
			&updatedUser.Status,
			&updatedUser.WebAuthnUserID,
			&updatedUser.RequestKey,
			&updatedUser.RequestEncEcdhPubkey,
			&updatedUser.RequestEncMlkemPubkey,
			&updatedUser.AnchorEs384PublicKey,
			&updatedUser.AnchorMldsa87PublicKey,
			&updatedUser.PubkeyBundleSignatureEs384,
			&updatedUser.PubkeyBundleSignatureMldsa87,
			&updatedUser.WrappedKeyEpoch,
			&allowedIPsCSV,
			&updatedUser.Ready,
		)
	if !s.db.IsNoRowsError(err) {
		var exists bool
		err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM v2_users WHERE id = $1)`, in.UserID).Scan(&exists)
		if err != nil {
			return nil, err
		}
		if !exists {
			return nil, ErrUserNotFound
		}
		return nil, ErrAlreadyFinalized
	} else if err != nil {
		return nil, err
	}

	updatedUser.AllowedIPs = parseAllowedIPsCSV(allowedIPsCSV)

	// Store the wrapped primary key, wrapped anchor, and first credential attestation on the user's single credential (the one created during registration)
	_, err = tx.Exec(ctx,
		`UPDATE v2_user_credentials
			SET wrapped_primary_key = $1,
				wrapped_anchor_key = $2,
				attestation_payload = $3,
				attestation_signature_es384 = $4,
				attestation_signature_mldsa87 = $5,
				wrapped_key_epoch = 1
			WHERE user_id = $6`,
		in.WrappedPrimaryKey, in.WrappedAnchorKey,
		in.AttestationPayload, in.AttestationSignatureEs384, in.AttestationSignatureMldsa87,
		in.UserID,
	)
	if err != nil {
		return nil, err
	}

	err = tx.Commit(ctx)
	if err != nil {
		return nil, err
	}

	return updatedUser, nil
}

func (s *AuthStore) GetCredentialForUser(ctx context.Context, userID, credentialID string) (*AuthCredentialRecord, error) {
	var rec AuthCredentialRecord
	err := s.db.
		QueryRow(ctx,
			`SELECT id, credential_id, display_name, public_key, sign_count, wrapped_primary_key, wrapped_anchor_key, attestation_payload, attestation_signature_es384, attestation_signature_mldsa87, wrapped_key_epoch, created_at, last_used_at
			FROM v2_user_credentials
			WHERE user_id = $1 AND credential_id = $2`,
			userID, credentialID,
		).
		Scan(
			&rec.ID,
			&rec.CredentialID,
			&rec.DisplayName,
			&rec.PublicKey,
			&rec.SignCount,
			&rec.WrappedPrimaryKey,
			&rec.WrappedAnchorKey,
			&rec.AttestationPayload,
			&rec.AttestationSignatureEs384,
			&rec.AttestationSignatureMldsa87,
			&rec.WrappedKeyEpoch,
			&rec.CreatedAt,
			&rec.LastUsedAt,
		)
	if s.db.IsNoRowsError(err) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}

	return &rec, nil
}

func (s *AuthStore) UpdateAllowedIPs(ctx context.Context, userID string, allowedIPs []string) ([]string, error) {
	normalized, err := NormalizeAllowedIPs(allowedIPs)
	if err != nil {
		return nil, err
	}

	// Only allow mutations for users that are active and have completed setup
	affected, err := s.db.Exec(ctx,
		`UPDATE v2_users SET allowed_ips = $1, updated_at = $2 WHERE id = $3 AND status = 'active' AND ready = true`,
		strings.Join(normalized, ","), time.Now().Unix(), userID,
	)
	if err != nil {
		return nil, err
	}

	if affected == 0 {
		return nil, ErrUserNotFound
	}

	return normalized, nil
}

func (s *AuthStore) RegenerateRequestKey(ctx context.Context, userID string) (string, error) {
	requestKey, err := utils.RandomString(20)
	if err != nil {
		return "", err
	}

	// Only allow mutations for users that are active and have completed setup
	affected, err := s.db.Exec(ctx,
		`UPDATE v2_users SET request_key = $1, updated_at = $2 WHERE id = $3 AND status = 'active' AND ready = true`,
		requestKey, time.Now().Unix(), userID,
	)
	if err != nil {
		return "", err
	}

	if affected == 0 {
		return "", ErrUserNotFound
	}

	return requestKey, nil
}

func (s *AuthStore) UpdateDisplayName(ctx context.Context, userID, displayName string) error {
	displayName = strings.TrimSpace(displayName)
	if len(displayName) > 100 {
		return ErrDisplayNameTooLong
	}

	affected, err := s.db.Exec(ctx,
		`UPDATE v2_users SET display_name = $1, updated_at = $2 WHERE id = $3 AND status = 'active' AND ready = true`,
		displayName, time.Now().Unix(), userID,
	)
	if err != nil {
		return err
	}

	if affected == 0 {
		return ErrUserNotFound
	}

	return nil
}

// UpdateCredentialWrappedKey updates the wrapped primary key and wrapped anchor key associated with a single credential
// The credential must belong to the given user
func (s *AuthStore) UpdateCredentialWrappedKey(ctx context.Context, credentialID, userID, wrappedPrimaryKey, wrappedAnchorKey string) error {
	if len(wrappedPrimaryKey) > 512 {
		return errors.New("wrappedPrimaryKey is too large")
	}
	if len(wrappedAnchorKey) > 32768 {
		return errors.New("wrappedAnchorKey is too large")
	}

	affected, err := s.db.Exec(ctx,
		`UPDATE v2_user_credentials SET wrapped_primary_key = $1, wrapped_anchor_key = $2, wrapped_key_epoch = (
			SELECT wrapped_key_epoch FROM v2_users WHERE id = $4
		)
			WHERE credential_id = $3 AND user_id = $4`,
		wrappedPrimaryKey, wrappedAnchorKey, credentialID, userID,
	)
	if err != nil {
		return err
	}

	if affected == 0 {
		return ErrCredentialNotFound
	}

	return nil
}

// HasPendingChallenge reports whether the user has an unconsumed, non-expired challenge of the given kind
func (s *AuthStore) HasPendingChallenge(ctx context.Context, userID, kind string) (bool, error) {
	now := time.Now().Unix()
	var exists bool
	err := s.db.
		QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM v2_auth_challenges WHERE user_id = $1 AND kind = $2 AND used_at IS NULL AND expires_at >= $3)`,
			userID, kind, now,
		).
		Scan(&exists)
	if err != nil {
		return false, err
	}
	return exists, nil
}

// GetCredentialByCredentialID returns the credential record matching credential_id (base64url encoded WebAuthn credential ID) for the given user
func (s *AuthStore) GetCredentialByCredentialID(ctx context.Context, credentialID, userID string) (*AuthCredentialRecord, error) {
	var rec AuthCredentialRecord
	err := s.db.QueryRow(ctx,
		`SELECT id, credential_id, display_name, public_key, sign_count, wrapped_primary_key, wrapped_anchor_key, attestation_payload, attestation_signature_es384, attestation_signature_mldsa87, wrapped_key_epoch, created_at, last_used_at
			FROM v2_user_credentials
			WHERE credential_id = $1 AND user_id = $2`,
		credentialID, userID,
	).Scan(&rec.ID, &rec.CredentialID, &rec.DisplayName, &rec.PublicKey, &rec.SignCount, &rec.WrappedPrimaryKey, &rec.WrappedAnchorKey, &rec.AttestationPayload, &rec.AttestationSignatureEs384, &rec.AttestationSignatureMldsa87, &rec.WrappedKeyEpoch, &rec.CreatedAt, &rec.LastUsedAt)
	if s.db.IsNoRowsError(err) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return &rec, nil
}

func (s *AuthStore) AddCredential(ctx context.Context, in AddCredentialInput) error {
	if len(in.WrappedPrimaryKey) > 512 {
		return errors.New("wrappedPrimaryKey is too large")
	}
	if len(in.WrappedAnchorKey) > 32768 {
		return errors.New("wrappedAnchorKey is too large")
	}
	if len(in.AttestationPayload) > 4096 {
		return errors.New("attestationPayload is too large")
	}

	now := time.Now().Unix()
	_, err := s.db.Exec(ctx,
		`INSERT INTO v2_user_credentials (
				id, user_id, credential_id, display_name, public_key, sign_count,
				wrapped_primary_key, wrapped_anchor_key,
				attestation_payload, attestation_signature_es384, attestation_signature_mldsa87,
				wrapped_key_epoch, created_at, last_used_at
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, (
				SELECT wrapped_key_epoch FROM v2_users WHERE id = $2
			), $12, $12)`,
		uuid.NewString(), in.UserID, in.CredentialID, in.DisplayName, in.PublicKey, in.SignCount,
		in.WrappedPrimaryKey, in.WrappedAnchorKey,
		in.AttestationPayload, in.AttestationSignatureEs384, in.AttestationSignatureMldsa87,
		now,
	)
	return err
}

func (s *AuthStore) AdvanceWrappedKeyEpoch(ctx context.Context, userID string) (int64, error) {
	var epoch int64
	err := s.db.
		QueryRow(ctx,
			`UPDATE v2_users SET wrapped_key_epoch = wrapped_key_epoch + 1, updated_at = $1 WHERE id = $2 AND status = 'active' AND ready = true RETURNING wrapped_key_epoch`,
			time.Now().Unix(), userID,
		).
		Scan(&epoch)
	if s.db.IsNoRowsError(err) {
		return 0, ErrUserNotFound
	}
	if err != nil {
		return 0, err
	}
	return epoch, nil
}

func (s *AuthStore) RenameCredential(ctx context.Context, id, userID, displayName string) error {
	displayName = strings.TrimSpace(displayName)
	if len(displayName) > 100 {
		return ErrDisplayNameTooLong
	}

	affected, err := s.db.Exec(ctx,
		`UPDATE v2_user_credentials SET display_name = $1 WHERE id = $2 AND user_id = $3`,
		displayName, id, userID,
	)
	if err != nil {
		return err
	}

	if affected == 0 {
		return ErrCredentialNotFound
	}

	return nil
}

func (s *AuthStore) DeleteCredential(ctx context.Context, id, userID string) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() {
		rollbackErr := tx.Rollback(ctx)
		if rollbackErr != nil && !s.db.IsTxDoneError(rollbackErr) {
			slog.Warn("Error rolling back transaction", slog.Any("err", rollbackErr))
		}
	}()

	var count int
	err = tx.QueryRow(ctx, `SELECT COUNT(*) FROM v2_user_credentials WHERE user_id = $1`, userID).Scan(&count)
	if err != nil {
		return err
	}

	if count <= 1 {
		return ErrLastCredential
	}

	affected, err := tx.Exec(ctx,
		`DELETE FROM v2_user_credentials WHERE id = $1 AND user_id = $2`,
		id, userID,
	)
	if err != nil {
		return err
	}

	if affected == 0 {
		return ErrCredentialNotFound
	}

	err = tx.Commit(ctx)
	if err != nil {
		return err
	}

	return nil
}

func (s *AuthStore) CleanupExpired(ctx context.Context, now time.Time) error {
	cutoff := now.Add(-10 * time.Minute).Unix()

	_, err := s.db.Exec(ctx,
		`DELETE FROM v2_auth_challenges WHERE expires_at < $1 OR used_at IS NOT NULL`,
		cutoff,
	)
	if err != nil {
		return fmt.Errorf("error deleting expired auth challenges: %w", err)
	}

	return nil
}

func (s *AuthStore) DeleteExpiredAuthChallenge(ctx context.Context, id string, now time.Time) error {
	cutoff := now.Add(-10 * time.Minute).Unix()
	_, err := s.db.Exec(ctx,
		`DELETE FROM v2_auth_challenges WHERE id = $1 AND (expires_at < $2 OR used_at IS NOT NULL)`,
		id, cutoff,
	)
	if err != nil {
		return fmt.Errorf("error deleting auth challenge: %w", err)
	}
	return nil
}

func (s *AuthStore) DeleteNonreadyUser(ctx context.Context, id string, now time.Time) error {
	cutoff := now.Add(-24*time.Hour - 10*time.Minute).Unix()
	_, err := s.db.Exec(ctx,
		`DELETE FROM v2_users WHERE id = $1 AND ready = false AND created_at < $2`,
		id, cutoff,
	)
	if err != nil {
		return fmt.Errorf("error deleting non-ready user: %w", err)
	}
	return nil
}

func NormalizeAllowedIPs(allowedIPs []string) ([]string, error) {
	seen := make(map[string]struct{}, len(allowedIPs))
	normalized := make([]string, 0, len(allowedIPs))

	for _, entry := range allowedIPs {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		var canonical string
		if strings.ContainsRune(entry, '/') {
			_, network, err := net.ParseCIDR(entry)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR: %s", entry)
			}
			canonical = network.String()
		} else {
			ip := net.ParseIP(entry)
			if ip == nil {
				return nil, fmt.Errorf("invalid IP: %s", entry)
			}
			canonical = ip.String()
		}

		_, ok := seen[canonical]
		if ok {
			continue
		}
		seen[canonical] = struct{}{}
		normalized = append(normalized, canonical)
	}

	return normalized, nil
}

func parseAllowedIPsCSV(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}

	parts := strings.Split(raw, ",")
	var j int
	for i := range parts {
		parts[j] = strings.TrimSpace(parts[i])
		if parts[j] != "" {
			j++
		}
	}
	parts = parts[:j]

	return parts
}

func isIntegrityViolationError(err error) bool {
	// These bits are set on all constraint-related errors
	// https://www.sqlite.org/rescode.html#constraint
	const sqliteConstraintCode = 19

	if err == nil {
		return false
	}

	// Handle SQLite errors
	sqliteErr, ok := errors.AsType[*sqlite.Error](err)
	if ok {
		return sqliteErr.Code()&sqliteConstraintCode != 0
	}

	// Handle Postgres errors
	pgErr, ok := errors.AsType[*pgconn.PgError](err)
	if ok {
		return pgerrcode.IsIntegrityConstraintViolation(pgErr.Code)
	}

	return false
}
