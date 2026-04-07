package v2db

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/italypaleale/revaulter/pkg/utils"
)

type AuthStore struct {
	db *DB
}

type User struct {
	ID             string
	DisplayName    string
	Status         string
	WebAuthnUserID string
	PasswordCanary string
	RequestKey     string
	AllowedIPs     []string
}

type AuthSession struct {
	ID          string
	UserID      string
	DisplayName string
	RequestKey  string
	AllowedIPs  []string
	ExpiresAt   time.Time
	CreatedAt   time.Time
}

type AuthChallenge struct {
	ID        string
	Kind      string
	UserID    string
	Challenge string
	ExpiresAt time.Time
}

type AuthCredentialRecord struct {
	CredentialID string
	PublicKey    string
	SignCount    int64
}

type RegisterUserInput struct {
	UserID         string
	DisplayName    string
	WebAuthnUserID string
	CredentialID   string
	PublicKey      string
	SignCount      int64
	SessionTTL     time.Duration
}

type LoginInput struct {
	UserID       string
	CredentialID string
	SignCount    int64
	SessionTTL   time.Duration
}

var (
	ErrUserAlreadyExists  = errors.New("user already exists")
	ErrUserNotFound       = errors.New("user not found")
	ErrInvalidLogin       = errors.New("invalid login")
	ErrPasswordAlreadySet = errors.New("password already set")
)

func NewAuthStore(db *DB, _ any) (*AuthStore, error) {
	if db == nil {
		return nil, errors.New("db is nil")
	}
	return &AuthStore{db: db}, nil
}

func (s *AuthStore) CountUsers(ctx context.Context) (int, error) {
	var n int
	err := s.db.db.QueryRow(ctx, `SELECT COUNT(*) FROM v2_users`).Scan(&n)
	return n, err
}

func (s *AuthStore) GetUserByID(ctx context.Context, userID string) (*User, error) {
	return s.getUser(ctx, `SELECT id, display_name, status, webauthn_user_id, password_canary, request_key, allowed_ips FROM v2_users WHERE id = $1`, userID)
}

func (s *AuthStore) GetUserByWebAuthnUserID(ctx context.Context, webAuthnUserID string) (*User, error) {
	return s.getUser(ctx, `SELECT id, display_name, status, webauthn_user_id, password_canary, request_key, allowed_ips FROM v2_users WHERE webauthn_user_id = $1`, webAuthnUserID)
}

func (s *AuthStore) GetUserByRequestKey(ctx context.Context, requestKey string) (*User, error) {
	return s.getUser(ctx, `SELECT id, display_name, status, webauthn_user_id, password_canary, request_key, allowed_ips FROM v2_users WHERE request_key = $1`, requestKey)
}

func (s *AuthStore) getUser(ctx context.Context, query string, arg string) (*User, error) {
	var (
		user          User
		allowedIPsCSV string
	)
	err := s.db.db.QueryRow(ctx, query, arg).
		Scan(&user.ID, &user.DisplayName, &user.Status, &user.WebAuthnUserID, &user.PasswordCanary, &user.RequestKey, &allowedIPsCSV)
	if s.db.db.IsNoRowsError(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	user.AllowedIPs = parseAllowedIPsCSV(allowedIPsCSV)
	return &user, nil
}

func (s *AuthStore) ListCredentials(ctx context.Context, userID string) ([]AuthCredentialRecord, error) {
	rows, err := s.db.db.Query(ctx,
		`SELECT credential_id, public_key, sign_count
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
		err = rows.Scan(&rec.CredentialID, &rec.PublicKey, &rec.SignCount)
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
	tx, err := s.db.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

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
	affected, err := s.db.db.Exec(ctx,
		`UPDATE v2_auth_challenges SET used_at = $1 WHERE id = $2 AND kind = $3 AND used_at IS NULL AND expires_at >= $4`,
		now, id, kind, now,
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
	err = s.db.db.
		QueryRow(ctx, `SELECT session_data FROM v2_auth_challenge_payloads WHERE challenge_id = $1`, id).
		Scan(&payload)
	if s.db.db.IsNoRowsError(err) {
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

func (s *AuthStore) RegisterUser(ctx context.Context, in RegisterUserInput) (*AuthSession, error) {
	tx, err := s.db.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	requestKey, err := utils.RandomString(20)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC().Unix()
	_, err = tx.Exec(ctx,
		`INSERT INTO v2_users (id, display_name, status, webauthn_user_id, password_canary, request_key, allowed_ips, created_at, updated_at)
		VALUES ($1, $2, 'active', $3, '', $4, '', $5, $6)`,
		in.UserID, in.DisplayName, in.WebAuthnUserID, requestKey, now, now,
	)
	if err != nil {
		return nil, err
	}

	_, err = tx.Exec(ctx,
		`INSERT INTO v2_user_credentials (id, user_id, credential_id, public_key, sign_count, created_at, last_used_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		uuid.NewString(), in.UserID, in.CredentialID, in.PublicKey, in.SignCount, now, now,
	)
	if err != nil {
		return nil, err
	}

	sess, err := insertSession(ctx, tx, in.UserID, in.SessionTTL)
	if err != nil {
		return nil, err
	}

	err = tx.Commit(ctx)
	if err != nil {
		return nil, err
	}
	return s.GetSession(ctx, sess.ID)
}

func (s *AuthStore) Login(ctx context.Context, in LoginInput) (*AuthSession, error) {
	tx, err := s.db.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

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
	if s.db.db.IsNoRowsError(err) {
		return nil, ErrInvalidLogin
	}
	if err != nil {
		return nil, err
	}

	sess, err := insertSession(ctx, tx, in.UserID, in.SessionTTL)
	if err != nil {
		return nil, err
	}

	err = tx.Commit(ctx)
	if err != nil {
		return nil, err
	}

	return s.GetSession(ctx, sess.ID)
}

func (s *AuthStore) GetSession(ctx context.Context, id string) (*AuthSession, error) {
	var (
		sess          AuthSession
		expiresAt     int64
		createdAt     int64
		revokedAt     sql.NullInt64
		allowedIPsCSV string
	)
	err := s.db.db.
		QueryRow(ctx,
			`SELECT s.id, s.user_id, u.display_name, u.request_key, u.allowed_ips, s.expires_at, s.created_at, s.revoked_at
			FROM v2_user_sessions s
			INNER JOIN v2_users u ON u.id = s.user_id
			WHERE s.id = $1 AND u.status = 'active'`,
			id,
		).
		Scan(&sess.ID, &sess.UserID, &sess.DisplayName, &sess.RequestKey, &allowedIPsCSV, &expiresAt, &createdAt, &revokedAt)
	if s.db.db.IsNoRowsError(err) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	if revokedAt.Valid {
		return nil, nil
	}

	sess.AllowedIPs = parseAllowedIPsCSV(allowedIPsCSV)
	sess.ExpiresAt = time.Unix(expiresAt, 0)
	sess.CreatedAt = time.Unix(createdAt, 0)
	if sess.ExpiresAt.Before(time.Now()) {
		return nil, nil
	}

	_ = s.touchSession(ctx, id)
	return &sess, nil
}

func (s *AuthStore) SetPasswordCanary(ctx context.Context, userID, canary string) error {
	affected, err := s.db.db.Exec(ctx,
		`UPDATE v2_users SET password_canary = $1, updated_at = $2 WHERE id = $3 AND password_canary = ''`,
		canary, time.Now().UTC().Unix(), userID,
	)
	if err != nil {
		return err
	}
	if affected == 1 {
		return nil
	}

	user, err := s.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}

	if user == nil {
		return ErrUserNotFound
	}

	return ErrPasswordAlreadySet
}

func (s *AuthStore) UpdateAllowedIPs(ctx context.Context, userID string, allowedIPs []string) ([]string, error) {
	normalized, err := NormalizeAllowedIPs(allowedIPs)
	if err != nil {
		return nil, err
	}

	affected, err := s.db.db.Exec(ctx,
		`UPDATE v2_users SET allowed_ips = $1, updated_at = $2 WHERE id = $3`,
		strings.Join(normalized, ","), time.Now().UTC().Unix(), userID,
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

	affected, err := s.db.db.Exec(ctx,
		`UPDATE v2_users SET request_key = $1, updated_at = $2 WHERE id = $3`,
		requestKey, time.Now().UTC().Unix(), userID,
	)
	if err != nil {
		return "", err
	}

	if affected == 0 {
		return "", ErrUserNotFound
	}

	return requestKey, nil
}

func (s *AuthStore) RevokeSession(ctx context.Context, id string) error {
	_, err := s.db.db.Exec(ctx, `UPDATE v2_user_sessions SET revoked_at = $1 WHERE id = $2`, time.Now().UTC().Unix(), id)
	return err
}

func (s *AuthStore) touchSession(ctx context.Context, id string) error {
	_, err := s.db.db.Exec(ctx, `UPDATE v2_user_sessions SET last_seen_at = $1 WHERE id = $2`, time.Now().UTC().Unix(), id)
	return err
}

type txExec interface {
	Exec(ctx context.Context, query string, args ...any) (int64, error)
}

func insertSession(ctx context.Context, tx txExec, userID string, ttl time.Duration) (*AuthSession, error) {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	now := time.Now().UTC()
	sess := &AuthSession{
		ID:        uuid.NewString(),
		UserID:    userID,
		CreatedAt: now,
		ExpiresAt: now.Add(ttl),
	}
	_, err := tx.Exec(ctx,
		`INSERT INTO v2_user_sessions (id, user_id, expires_at, created_at, last_seen_at) VALUES ($1, $2, $3, $4, $5)`,
		sess.ID, sess.UserID, sess.ExpiresAt.Unix(), sess.CreatedAt.Unix(), sess.CreatedAt.Unix(),
	)
	return sess, err
}

func (s *AuthStore) CleanupExpired(ctx context.Context, now time.Time) error {
	cutoff := now.Add(-10 * time.Minute).Unix()

	_, err := s.db.db.Exec(ctx,
		`DELETE FROM v2_auth_challenges WHERE expires_at < $1 OR used_at IS NOT NULL`,
		cutoff,
	)
	if err != nil {
		return fmt.Errorf("error deleting expired auth challenges: %w", err)
	}

	_, err = s.db.db.Exec(ctx,
		`DELETE FROM v2_user_sessions WHERE expires_at < $1 OR (revoked_at IS NOT NULL AND revoked_at < $2)`,
		cutoff, cutoff,
	)
	if err != nil {
		return fmt.Errorf("error deleting expired user sessions: %w", err)
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
