package v2db

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/italypaleale/go-sql-utils/migrations"
	pgmigrations "github.com/italypaleale/go-sql-utils/migrations/postgres"
	sqlitemigrations "github.com/italypaleale/go-sql-utils/migrations/sqlite"
)

type AuthStore struct {
	db   *DB
	log  *slog.Logger
	aead cipher.AEAD
}

type Admin struct {
	ID             string
	Username       string
	DisplayName    string
	Status         string
	WebAuthnUserID string
}

type AuthSession struct {
	ID               string
	AdminID          string
	Username         string
	PasswordVerified bool
	ExpiresAt        time.Time
	CreatedAt        time.Time
}

type AuthChallenge struct {
	ID        string
	Kind      string
	Username  string
	Challenge string
	ExpiresAt time.Time
}

type AuthCredentialRecord struct {
	CredentialID string
	PublicKey    string
	SignCount    int64
}

type PasswordFactorRecord struct {
	AdminID    string
	Username   string
	Salt       string
	Iterations int
	AuthKey    string
	Enabled    bool
}

type PasswordFactorEnrollment struct {
	Salt       string
	Iterations int
	AuthKey    string
}

type RegisterFirstAdminInput struct {
	Username       string
	DisplayName    string
	WebAuthnUserID string
	CredentialID   string
	PublicKey      string
	SignCount      int64
	PasswordFactor *PasswordFactorEnrollment
	SessionTTL     time.Duration
}

type RegisterAdminInput struct {
	Username       string
	DisplayName    string
	WebAuthnUserID string
	CredentialID   string
	PublicKey      string
	SignCount      int64
	PasswordFactor *PasswordFactorEnrollment
}

type LoginInput struct {
	Username         string
	CredentialID     string
	SignCount        int64
	PasswordVerified bool
	SessionTTL       time.Duration
}

func NewAuthStore(ctx context.Context, db *DB, logger *slog.Logger) (*AuthStore, error) {
	return NewAuthStoreWithPayloadKey(ctx, db, nil, logger)
}

func NewAuthStoreWithPayloadKey(ctx context.Context, db *DB, payloadKey []byte, logger *slog.Logger) (*AuthStore, error) {
	if db == nil {
		return nil, errors.New("db is nil")
	}
	if logger == nil {
		logger = slog.Default()
	}
	var aead cipher.AEAD
	if len(payloadKey) > 0 {
		if len(payloadKey) != 32 {
			return nil, errors.New("invalid payload key length for auth store")
		}
		block, err := aes.NewCipher(payloadKey)
		if err != nil {
			return nil, err
		}
		aead, err = cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
	}
	s := &AuthStore{db: db, log: logger, aead: aead}
	if err := s.migrate(ctx); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *AuthStore) migrate(ctx context.Context) error {
	switch s.db.Backend {
	case BackendSQLite:
		m := &sqlitemigrations.Migrations{
			Pool:              s.db.SQLite,
			MetadataTableName: "_revaulter_v2_migrations",
			MetadataKey:       "auth",
		}
		return m.Perform(ctx, []migrations.MigrationFn{
			func(ctx context.Context) error {
				return s.migrationSQLite(ctx, m.GetConn())
			},
			func(ctx context.Context) error {
				return s.migrationSQLitePasswordFactor(ctx, m.GetConn())
			},
			func(ctx context.Context) error {
				return s.migrationSQLiteWebAuthnUserID(ctx, m.GetConn())
			},
		}, s.log)
	case BackendPostgres:
		m := pgmigrations.Migrations{
			DB:                s.db.Postgres,
			MetadataTableName: "_revaulter_v2_migrations",
			MetadataKey:       "auth",
		}
		return m.Perform(ctx, []migrations.MigrationFn{s.migrationPostgres, s.migrationPostgresPasswordFactor, s.migrationPostgresWebAuthnUserID}, s.log)
	default:
		return errors.New("unsupported backend")
	}
}

func (s *AuthStore) migrationSQLite(ctx context.Context, conn *sql.Conn) error {
	if conn == nil {
		return errors.New("sqlite migration connection is nil")
	}
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS v2_admins (
			id TEXT PRIMARY KEY,
			username TEXT NOT NULL UNIQUE,
			display_name TEXT NOT NULL,
			status TEXT NOT NULL,
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS v2_admin_credentials (
			id TEXT PRIMARY KEY,
			admin_id TEXT NOT NULL,
			credential_id TEXT NOT NULL UNIQUE,
			public_key TEXT NOT NULL,
			sign_count INTEGER NOT NULL,
			created_at INTEGER NOT NULL,
			last_used_at INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS v2_auth_challenges (
			id TEXT PRIMARY KEY,
			kind TEXT NOT NULL,
			username TEXT NOT NULL,
			challenge TEXT NOT NULL,
			expires_at INTEGER NOT NULL,
			used_at INTEGER
		)`,
		`CREATE TABLE IF NOT EXISTS v2_auth_challenge_payloads (
			challenge_id TEXT PRIMARY KEY,
			session_data TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS v2_admin_sessions (
			id TEXT PRIMARY KEY,
			admin_id TEXT NOT NULL,
			username TEXT NOT NULL,
			expires_at INTEGER NOT NULL,
			created_at INTEGER NOT NULL,
			last_seen_at INTEGER NOT NULL,
			revoked_at INTEGER
		)`,
		`CREATE INDEX IF NOT EXISTS idx_v2_auth_challenges_lookup ON v2_auth_challenges(kind, username, expires_at)`,
		`CREATE INDEX IF NOT EXISTS idx_v2_admin_sessions_lookup ON v2_admin_sessions(username, expires_at)`,
	}
	for _, stmt := range stmts {
		if _, err := conn.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	return nil
}

func (s *AuthStore) migrationPostgres(ctx context.Context) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS v2_admins (
			id text PRIMARY KEY,
			username text NOT NULL UNIQUE,
			display_name text NOT NULL,
			status text NOT NULL,
			created_at bigint NOT NULL,
			updated_at bigint NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS v2_admin_credentials (
			id text PRIMARY KEY,
			admin_id text NOT NULL,
			credential_id text NOT NULL UNIQUE,
			public_key text NOT NULL,
			sign_count bigint NOT NULL,
			created_at bigint NOT NULL,
			last_used_at bigint NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS v2_auth_challenges (
			id text PRIMARY KEY,
			kind text NOT NULL,
			username text NOT NULL,
			challenge text NOT NULL,
			expires_at bigint NOT NULL,
			used_at bigint
		)`,
		`CREATE TABLE IF NOT EXISTS v2_auth_challenge_payloads (
			challenge_id text PRIMARY KEY,
			session_data text NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS v2_admin_sessions (
			id text PRIMARY KEY,
			admin_id text NOT NULL,
			username text NOT NULL,
			expires_at bigint NOT NULL,
			created_at bigint NOT NULL,
			last_seen_at bigint NOT NULL,
			revoked_at bigint
		)`,
		`CREATE INDEX IF NOT EXISTS idx_v2_auth_challenges_lookup ON v2_auth_challenges(kind, username, expires_at)`,
		`CREATE INDEX IF NOT EXISTS idx_v2_admin_sessions_lookup ON v2_admin_sessions(username, expires_at)`,
	}
	for _, stmt := range stmts {
		if _, err := s.db.Postgres.Exec(ctx, stmt); err != nil {
			return err
		}
	}
	return nil
}

func (s *AuthStore) migrationSQLitePasswordFactor(ctx context.Context, conn *sql.Conn) error {
	if conn == nil {
		return errors.New("sqlite migration connection is nil")
	}
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS v2_admin_password_factors (
			admin_id TEXT PRIMARY KEY,
			salt TEXT NOT NULL,
			pbkdf2_iterations INTEGER NOT NULL,
			auth_key TEXT NOT NULL,
			enabled INTEGER NOT NULL DEFAULT 1,
			created_at INTEGER NOT NULL,
			rotated_at INTEGER NOT NULL
		)`,
		`ALTER TABLE v2_admin_sessions ADD COLUMN password_verified INTEGER NOT NULL DEFAULT 0`,
	}
	for _, stmt := range stmts {
		if _, err := conn.ExecContext(ctx, stmt); err != nil {
			if isIgnorableSQLiteMigrationError(err) {
				continue
			}
			return err
		}
	}
	return nil
}

func (s *AuthStore) migrationPostgresPasswordFactor(ctx context.Context) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS v2_admin_password_factors (
			admin_id text PRIMARY KEY,
			salt text NOT NULL,
			pbkdf2_iterations integer NOT NULL,
			auth_key text NOT NULL,
			enabled smallint NOT NULL DEFAULT 1,
			created_at bigint NOT NULL,
			rotated_at bigint NOT NULL
		)`,
		`ALTER TABLE v2_admin_sessions ADD COLUMN password_verified smallint NOT NULL DEFAULT 0`,
	}
	for _, stmt := range stmts {
		if _, err := s.db.Postgres.Exec(ctx, stmt); err != nil {
			if isIgnorablePostgresMigrationError(err) {
				continue
			}
			return err
		}
	}
	return nil
}

func (s *AuthStore) migrationSQLiteWebAuthnUserID(ctx context.Context, conn *sql.Conn) error {
	if conn == nil {
		return errors.New("sqlite migration connection is nil")
	}
	_, err := conn.ExecContext(ctx, `ALTER TABLE v2_admins ADD COLUMN webauthn_user_id TEXT NOT NULL DEFAULT ''`)
	if err != nil && !isIgnorableSQLiteMigrationError(err) {
		return err
	}
	return nil
}

func (s *AuthStore) migrationPostgresWebAuthnUserID(ctx context.Context) error {
	_, err := s.db.Postgres.Exec(ctx, `ALTER TABLE v2_admins ADD COLUMN webauthn_user_id text NOT NULL DEFAULT ''`)
	if err != nil && !isIgnorablePostgresMigrationError(err) {
		return err
	}
	return nil
}

func (s *AuthStore) CountAdmins(ctx context.Context) (int, error) {
	var n int
	var err error
	switch s.db.Backend {
	case BackendSQLite:
		err = s.db.SQLite.QueryRowContext(ctx, `SELECT COUNT(*) FROM v2_admins`).Scan(&n)
	case BackendPostgres:
		err = s.db.Postgres.QueryRow(ctx, `SELECT COUNT(*) FROM v2_admins`).Scan(&n)
	default:
		err = errors.New("unsupported backend")
	}
	return n, err
}

func (s *AuthStore) GetAdminByUsername(ctx context.Context, username string) (*Admin, error) {
	var a Admin
	var err error
	switch s.db.Backend {
	case BackendSQLite:
		err = s.db.SQLite.QueryRowContext(ctx, `SELECT id, username, display_name, status, webauthn_user_id FROM v2_admins WHERE username = ?`, username).
			Scan(&a.ID, &a.Username, &a.DisplayName, &a.Status, &a.WebAuthnUserID)
	case BackendPostgres:
		err = s.db.Postgres.QueryRow(ctx, `SELECT id, username, display_name, status, webauthn_user_id FROM v2_admins WHERE username = $1`, username).
			Scan(&a.ID, &a.Username, &a.DisplayName, &a.Status, &a.WebAuthnUserID)
	default:
		err = errors.New("unsupported backend")
	}
	if errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &a, nil
}

func (s *AuthStore) ListCredentialIDs(ctx context.Context, username string) ([]string, error) {
	switch s.db.Backend {
	case BackendSQLite:
		rows, err := s.db.SQLite.QueryContext(ctx, `SELECT c.credential_id FROM v2_admin_credentials c INNER JOIN v2_admins a ON a.id = c.admin_id WHERE a.username = ? ORDER BY c.created_at ASC`, username)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var out []string
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return nil, err
			}
			out = append(out, id)
		}
		return out, rows.Err()
	case BackendPostgres:
		rows, err := s.db.Postgres.Query(ctx, `SELECT c.credential_id FROM v2_admin_credentials c INNER JOIN v2_admins a ON a.id = c.admin_id WHERE a.username = $1 ORDER BY c.created_at ASC`, username)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var out []string
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return nil, err
			}
			out = append(out, id)
		}
		return out, rows.Err()
	default:
		return nil, errors.New("unsupported backend")
	}
}

func (s *AuthStore) ListCredentials(ctx context.Context, username string) ([]AuthCredentialRecord, error) {
	switch s.db.Backend {
	case BackendSQLite:
		rows, err := s.db.SQLite.QueryContext(ctx, `SELECT c.credential_id, c.public_key, c.sign_count
			FROM v2_admin_credentials c
			INNER JOIN v2_admins a ON a.id = c.admin_id
			WHERE a.username = ?
			ORDER BY c.created_at ASC`, username)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var out []AuthCredentialRecord
		for rows.Next() {
			var r AuthCredentialRecord
			if err := rows.Scan(&r.CredentialID, &r.PublicKey, &r.SignCount); err != nil {
				return nil, err
			}
			out = append(out, r)
		}
		return out, rows.Err()
	case BackendPostgres:
		rows, err := s.db.Postgres.Query(ctx, `SELECT c.credential_id, c.public_key, c.sign_count
			FROM v2_admin_credentials c
			INNER JOIN v2_admins a ON a.id = c.admin_id
			WHERE a.username = $1
			ORDER BY c.created_at ASC`, username)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var out []AuthCredentialRecord
		for rows.Next() {
			var r AuthCredentialRecord
			if err := rows.Scan(&r.CredentialID, &r.PublicKey, &r.SignCount); err != nil {
				return nil, err
			}
			out = append(out, r)
		}
		return out, rows.Err()
	default:
		return nil, errors.New("unsupported backend")
	}
}

func (s *AuthStore) GetPasswordFactorByUsername(ctx context.Context, username string) (*PasswordFactorRecord, error) {
	var rec PasswordFactorRecord
	var enabled int
	var err error
	switch s.db.Backend {
	case BackendSQLite:
		err = s.db.SQLite.QueryRowContext(ctx, `SELECT p.admin_id, a.username, p.salt, p.pbkdf2_iterations, p.auth_key, p.enabled
			FROM v2_admin_password_factors p
			INNER JOIN v2_admins a ON a.id = p.admin_id
			WHERE a.username = ?`, username).
			Scan(&rec.AdminID, &rec.Username, &rec.Salt, &rec.Iterations, &rec.AuthKey, &enabled)
	case BackendPostgres:
		err = s.db.Postgres.QueryRow(ctx, `SELECT p.admin_id, a.username, p.salt, p.pbkdf2_iterations, p.auth_key, p.enabled
			FROM v2_admin_password_factors p
			INNER JOIN v2_admins a ON a.id = p.admin_id
			WHERE a.username = $1`, username).
			Scan(&rec.AdminID, &rec.Username, &rec.Salt, &rec.Iterations, &rec.AuthKey, &enabled)
	default:
		err = errors.New("unsupported backend")
	}
	if errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if rec.AuthKey != "" {
		authKey, err := s.openSecret("password-auth-key", rec.AdminID, rec.AuthKey)
		if err != nil {
			return nil, err
		}
		rec.AuthKey = authKey
	}
	rec.Enabled = enabled != 0
	return &rec, nil
}

func (s *AuthStore) BeginChallenge(ctx context.Context, kind, username string, ttl time.Duration) (*AuthChallenge, error) {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	ch := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, ch); err != nil {
		return nil, err
	}
	id := uuid.NewString()
	now := time.Now().UTC()
	rec := &AuthChallenge{
		ID:        id,
		Kind:      kind,
		Username:  username,
		Challenge: base64.RawURLEncoding.EncodeToString(ch),
		ExpiresAt: now.Add(ttl),
	}
	return rec, s.insertChallenge(ctx, rec, nil)
}

func (s *AuthStore) BeginChallengeWithPayload(ctx context.Context, kind, username string, challenge string, expiresAt time.Time, payload any) (*AuthChallenge, error) {
	if challenge == "" {
		return nil, errors.New("challenge is empty")
	}
	if expiresAt.IsZero() {
		expiresAt = time.Now().UTC().Add(5 * time.Minute)
	}
	rec := &AuthChallenge{
		ID:        uuid.NewString(),
		Kind:      kind,
		Username:  username,
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
	var err error
	switch s.db.Backend {
	case BackendSQLite:
		_, err = s.db.SQLite.ExecContext(ctx, `INSERT INTO v2_auth_challenges (id, kind, username, challenge, expires_at) VALUES (?, ?, ?, ?, ?)`,
			rec.ID, rec.Kind, rec.Username, rec.Challenge, rec.ExpiresAt.Unix())
		if err == nil && len(payload) > 0 {
			_, err = s.db.SQLite.ExecContext(ctx, `INSERT INTO v2_auth_challenge_payloads (challenge_id, session_data) VALUES (?, ?)`, rec.ID, string(payload))
		}
	case BackendPostgres:
		_, err = s.db.Postgres.Exec(ctx, `INSERT INTO v2_auth_challenges (id, kind, username, challenge, expires_at) VALUES ($1,$2,$3,$4,$5)`,
			rec.ID, rec.Kind, rec.Username, rec.Challenge, rec.ExpiresAt.Unix())
		if err == nil && len(payload) > 0 {
			_, err = s.db.Postgres.Exec(ctx, `INSERT INTO v2_auth_challenge_payloads (challenge_id, session_data) VALUES ($1, $2)`, rec.ID, string(payload))
		}
	default:
		err = errors.New("unsupported backend")
	}
	return err
}

func (s *AuthStore) ConsumeChallenge(ctx context.Context, id, kind, username string) (bool, error) {
	now := time.Now().Unix()
	switch s.db.Backend {
	case BackendSQLite:
		res, err := s.db.SQLite.ExecContext(ctx, `UPDATE v2_auth_challenges SET used_at = ? WHERE id = ? AND kind = ? AND username = ? AND used_at IS NULL AND expires_at >= ?`,
			now, id, kind, username, now)
		if err != nil {
			return false, err
		}
		n, _ := res.RowsAffected()
		return n == 1, nil
	case BackendPostgres:
		tag, err := s.db.Postgres.Exec(ctx, `UPDATE v2_auth_challenges SET used_at = $1 WHERE id = $2 AND kind = $3 AND username = $4 AND used_at IS NULL AND expires_at >= $5`,
			now, id, kind, username, now)
		if err != nil {
			return false, err
		}
		return tag.RowsAffected() == 1, nil
	default:
		return false, errors.New("unsupported backend")
	}
}

func (s *AuthStore) ConsumeChallengePayload(ctx context.Context, id, kind, username string, out any) (bool, error) {
	ok, err := s.ConsumeChallenge(ctx, id, kind, username)
	if err != nil || !ok {
		return ok, err
	}
	if out == nil {
		return true, nil
	}
	var payload string
	switch s.db.Backend {
	case BackendSQLite:
		err = s.db.SQLite.QueryRowContext(ctx, `SELECT session_data FROM v2_auth_challenge_payloads WHERE challenge_id = ?`, id).Scan(&payload)
	case BackendPostgres:
		err = s.db.Postgres.QueryRow(ctx, `SELECT session_data FROM v2_auth_challenge_payloads WHERE challenge_id = $1`, id).Scan(&payload)
	default:
		err = errors.New("unsupported backend")
	}
	if errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	if err := json.Unmarshal([]byte(payload), out); err != nil {
		return false, err
	}
	return true, nil
}

func (s *AuthStore) RegisterFirstAdmin(ctx context.Context, in RegisterFirstAdminInput) (*AuthSession, error) {
	switch s.db.Backend {
	case BackendSQLite:
		return s.registerFirstAdminSQLite(ctx, in)
	case BackendPostgres:
		return s.registerFirstAdminPostgres(ctx, in)
	default:
		return nil, errors.New("unsupported backend")
	}
}

func (s *AuthStore) RegisterAdmin(ctx context.Context, in RegisterAdminInput) error {
	switch s.db.Backend {
	case BackendSQLite:
		return s.registerAdminSQLite(ctx, in)
	case BackendPostgres:
		return s.registerAdminPostgres(ctx, in)
	default:
		return errors.New("unsupported backend")
	}
}

func (s *AuthStore) Login(ctx context.Context, in LoginInput) (*AuthSession, error) {
	switch s.db.Backend {
	case BackendSQLite:
		return s.loginSQLite(ctx, in)
	case BackendPostgres:
		return s.loginPostgres(ctx, in)
	default:
		return nil, errors.New("unsupported backend")
	}
}

func (s *AuthStore) GetSession(ctx context.Context, id string) (*AuthSession, error) {
	var sess AuthSession
	var expiresAt, createdAt, revokedAt sql.NullInt64
	var passwordVerified int
	var err error
	switch s.db.Backend {
	case BackendSQLite:
		err = s.db.SQLite.QueryRowContext(ctx, `SELECT id, admin_id, username, password_verified, expires_at, created_at, revoked_at FROM v2_admin_sessions WHERE id = ?`, id).
			Scan(&sess.ID, &sess.AdminID, &sess.Username, &passwordVerified, &expiresAt, &createdAt, &revokedAt)
	case BackendPostgres:
		err = s.db.Postgres.QueryRow(ctx, `SELECT id, admin_id, username, password_verified, expires_at, created_at, revoked_at FROM v2_admin_sessions WHERE id = $1`, id).
			Scan(&sess.ID, &sess.AdminID, &sess.Username, &passwordVerified, &expiresAt, &createdAt, &revokedAt)
	default:
		err = errors.New("unsupported backend")
	}
	if errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if revokedAt.Valid {
		return nil, nil
	}
	sess.PasswordVerified = passwordVerified != 0
	sess.ExpiresAt = time.Unix(expiresAt.Int64, 0)
	sess.CreatedAt = time.Unix(createdAt.Int64, 0)
	if sess.ExpiresAt.Before(time.Now()) {
		return nil, nil
	}
	_ = s.touchSession(ctx, id)
	return &sess, nil
}

func (s *AuthStore) RevokeSession(ctx context.Context, id string) error {
	now := time.Now().Unix()
	switch s.db.Backend {
	case BackendSQLite:
		_, err := s.db.SQLite.ExecContext(ctx, `UPDATE v2_admin_sessions SET revoked_at = ? WHERE id = ?`, now, id)
		return err
	case BackendPostgres:
		_, err := s.db.Postgres.Exec(ctx, `UPDATE v2_admin_sessions SET revoked_at = $1 WHERE id = $2`, now, id)
		return err
	default:
		return errors.New("unsupported backend")
	}
}

func (s *AuthStore) touchSession(ctx context.Context, id string) error {
	now := time.Now().Unix()
	switch s.db.Backend {
	case BackendSQLite:
		_, err := s.db.SQLite.ExecContext(ctx, `UPDATE v2_admin_sessions SET last_seen_at = ? WHERE id = ?`, now, id)
		return err
	case BackendPostgres:
		_, err := s.db.Postgres.Exec(ctx, `UPDATE v2_admin_sessions SET last_seen_at = $1 WHERE id = $2`, now, id)
		return err
	default:
		return errors.New("unsupported backend")
	}
}

func (s *AuthStore) registerFirstAdminSQLite(ctx context.Context, in RegisterFirstAdminInput) (*AuthSession, error) {
	tx, err := s.db.SQLite.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	var n int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM v2_admins`).Scan(&n); err != nil {
		return nil, err
	}
	if n > 0 {
		return nil, ErrFirstAdminAlreadyExists
	}

	now := time.Now().UTC()
	adminID := uuid.NewString()
	if _, err := tx.ExecContext(ctx, `INSERT INTO v2_admins (id, username, display_name, status, webauthn_user_id, created_at, updated_at) VALUES (?, ?, ?, 'active', ?, ?, ?)`,
		adminID, in.Username, in.DisplayName, in.WebAuthnUserID, now.Unix(), now.Unix()); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO v2_admin_credentials (id, admin_id, credential_id, public_key, sign_count, created_at, last_used_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		uuid.NewString(), adminID, in.CredentialID, in.PublicKey, in.SignCount, now.Unix(), now.Unix()); err != nil {
		return nil, err
	}
	if in.PasswordFactor != nil {
		encAuthKey, err := s.sealSecret("password-auth-key", adminID, in.PasswordFactor.AuthKey)
		if err != nil {
			return nil, err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO v2_admin_password_factors (admin_id, salt, pbkdf2_iterations, auth_key, enabled, created_at, rotated_at) VALUES (?, ?, ?, ?, 1, ?, ?)`,
			adminID, in.PasswordFactor.Salt, in.PasswordFactor.Iterations, encAuthKey, now.Unix(), now.Unix()); err != nil {
			return nil, err
		}
	}
	sess, err := insertSessionSQLite(ctx, tx, adminID, in.Username, in.PasswordFactor != nil, in.SessionTTL)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return sess, nil
}

func (s *AuthStore) registerAdminSQLite(ctx context.Context, in RegisterAdminInput) error {
	tx, err := s.db.SQLite.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var n int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM v2_admins WHERE username = ?`, in.Username).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return ErrAdminAlreadyExists
	}

	now := time.Now().UTC()
	adminID := uuid.NewString()
	if _, err := tx.ExecContext(ctx, `INSERT INTO v2_admins (id, username, display_name, status, webauthn_user_id, created_at, updated_at) VALUES (?, ?, ?, 'active', ?, ?, ?)`,
		adminID, in.Username, in.DisplayName, in.WebAuthnUserID, now.Unix(), now.Unix()); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO v2_admin_credentials (id, admin_id, credential_id, public_key, sign_count, created_at, last_used_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		uuid.NewString(), adminID, in.CredentialID, in.PublicKey, in.SignCount, now.Unix(), now.Unix()); err != nil {
		return err
	}
	if in.PasswordFactor != nil {
		encAuthKey, err := s.sealSecret("password-auth-key", adminID, in.PasswordFactor.AuthKey)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO v2_admin_password_factors (admin_id, salt, pbkdf2_iterations, auth_key, enabled, created_at, rotated_at) VALUES (?, ?, ?, ?, 1, ?, ?)`,
			adminID, in.PasswordFactor.Salt, in.PasswordFactor.Iterations, encAuthKey, now.Unix(), now.Unix()); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *AuthStore) registerFirstAdminPostgres(ctx context.Context, in RegisterFirstAdminInput) (*AuthSession, error) {
	tx, err := s.db.Postgres.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	var n int
	if err := tx.QueryRow(ctx, `SELECT COUNT(*) FROM v2_admins`).Scan(&n); err != nil {
		return nil, err
	}
	if n > 0 {
		return nil, ErrFirstAdminAlreadyExists
	}

	now := time.Now().UTC()
	adminID := uuid.NewString()
	if _, err := tx.Exec(ctx, `INSERT INTO v2_admins (id, username, display_name, status, webauthn_user_id, created_at, updated_at) VALUES ($1,$2,$3,'active',$4,$5,$6)`,
		adminID, in.Username, in.DisplayName, in.WebAuthnUserID, now.Unix(), now.Unix()); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO v2_admin_credentials (id, admin_id, credential_id, public_key, sign_count, created_at, last_used_at) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		uuid.NewString(), adminID, in.CredentialID, in.PublicKey, in.SignCount, now.Unix(), now.Unix()); err != nil {
		return nil, err
	}
	if in.PasswordFactor != nil {
		encAuthKey, err := s.sealSecret("password-auth-key", adminID, in.PasswordFactor.AuthKey)
		if err != nil {
			return nil, err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO v2_admin_password_factors (admin_id, salt, pbkdf2_iterations, auth_key, enabled, created_at, rotated_at) VALUES ($1,$2,$3,$4,1,$5,$6)`,
			adminID, in.PasswordFactor.Salt, in.PasswordFactor.Iterations, encAuthKey, now.Unix(), now.Unix()); err != nil {
			return nil, err
		}
	}
	sess, err := insertSessionPgx(ctx, tx, adminID, in.Username, in.PasswordFactor != nil, in.SessionTTL)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return sess, nil
}

func (s *AuthStore) registerAdminPostgres(ctx context.Context, in RegisterAdminInput) error {
	tx, err := s.db.Postgres.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	var n int
	if err := tx.QueryRow(ctx, `SELECT COUNT(*) FROM v2_admins WHERE username = $1`, in.Username).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return ErrAdminAlreadyExists
	}

	now := time.Now().UTC()
	adminID := uuid.NewString()
	if _, err := tx.Exec(ctx, `INSERT INTO v2_admins (id, username, display_name, status, webauthn_user_id, created_at, updated_at) VALUES ($1,$2,$3,'active',$4,$5,$6)`,
		adminID, in.Username, in.DisplayName, in.WebAuthnUserID, now.Unix(), now.Unix()); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO v2_admin_credentials (id, admin_id, credential_id, public_key, sign_count, created_at, last_used_at) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		uuid.NewString(), adminID, in.CredentialID, in.PublicKey, in.SignCount, now.Unix(), now.Unix()); err != nil {
		return err
	}
	if in.PasswordFactor != nil {
		encAuthKey, err := s.sealSecret("password-auth-key", adminID, in.PasswordFactor.AuthKey)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO v2_admin_password_factors (admin_id, salt, pbkdf2_iterations, auth_key, enabled, created_at, rotated_at) VALUES ($1,$2,$3,$4,1,$5,$6)`,
			adminID, in.PasswordFactor.Salt, in.PasswordFactor.Iterations, encAuthKey, now.Unix(), now.Unix()); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (s *AuthStore) loginSQLite(ctx context.Context, in LoginInput) (*AuthSession, error) {
	tx, err := s.db.SQLite.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	var adminID string
	err = tx.QueryRowContext(ctx, `SELECT a.id FROM v2_admins a INNER JOIN v2_admin_credentials c ON c.admin_id = a.id WHERE a.username = ? AND c.credential_id = ? AND a.status = 'active'`,
		in.Username, in.CredentialID).Scan(&adminID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrInvalidLogin
	}
	if err != nil {
		return nil, err
	}
	now := time.Now().Unix()
	if _, err := tx.ExecContext(ctx, `UPDATE v2_admin_credentials SET sign_count = ?, last_used_at = ? WHERE credential_id = ?`, in.SignCount, now, in.CredentialID); err != nil {
		return nil, err
	}
	sess, err := insertSessionSQLite(ctx, tx, adminID, in.Username, in.PasswordVerified, in.SessionTTL)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return sess, nil
}

func (s *AuthStore) loginPostgres(ctx context.Context, in LoginInput) (*AuthSession, error) {
	tx, err := s.db.Postgres.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	var adminID string
	err = tx.QueryRow(ctx, `SELECT a.id FROM v2_admins a INNER JOIN v2_admin_credentials c ON c.admin_id = a.id WHERE a.username = $1 AND c.credential_id = $2 AND a.status = 'active'`,
		in.Username, in.CredentialID).Scan(&adminID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrInvalidLogin
	}
	if err != nil {
		return nil, err
	}
	now := time.Now().Unix()
	if _, err := tx.Exec(ctx, `UPDATE v2_admin_credentials SET sign_count = $1, last_used_at = $2 WHERE credential_id = $3`, in.SignCount, now, in.CredentialID); err != nil {
		return nil, err
	}
	sess, err := insertSessionPgx(ctx, tx, adminID, in.Username, in.PasswordVerified, in.SessionTTL)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return sess, nil
}

var (
	ErrFirstAdminAlreadyExists = errors.New("first admin already exists")
	ErrAdminAlreadyExists      = errors.New("admin already exists")
	ErrInvalidLogin            = errors.New("invalid login")
)

func insertSessionSQLite(ctx context.Context, tx *sql.Tx, adminID, username string, passwordVerified bool, ttl time.Duration) (*AuthSession, error) {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	now := time.Now().UTC()
	sess := &AuthSession{
		ID:               uuid.NewString(),
		AdminID:          adminID,
		Username:         username,
		PasswordVerified: passwordVerified,
		CreatedAt:        now,
		ExpiresAt:        now.Add(ttl),
	}
	pw := 0
	if passwordVerified {
		pw = 1
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO v2_admin_sessions (id, admin_id, username, password_verified, expires_at, created_at, last_seen_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		sess.ID, sess.AdminID, sess.Username, pw, sess.ExpiresAt.Unix(), sess.CreatedAt.Unix(), sess.CreatedAt.Unix())
	return sess, err
}

func insertSessionPgx(ctx context.Context, tx pgx.Tx, adminID, username string, passwordVerified bool, ttl time.Duration) (*AuthSession, error) {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	now := time.Now().UTC()
	sess := &AuthSession{
		ID:               uuid.NewString(),
		AdminID:          adminID,
		Username:         username,
		PasswordVerified: passwordVerified,
		CreatedAt:        now,
		ExpiresAt:        now.Add(ttl),
	}
	pw := 0
	if passwordVerified {
		pw = 1
	}
	_, err := tx.Exec(ctx, `INSERT INTO v2_admin_sessions (id, admin_id, username, password_verified, expires_at, created_at, last_seen_at) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		sess.ID, sess.AdminID, sess.Username, pw, sess.ExpiresAt.Unix(), sess.CreatedAt.Unix(), sess.CreatedAt.Unix())
	return sess, err
}

func VerifyPasswordProof(authKeyB64, proofB64 string, message []byte) bool {
	key, err := base64.RawURLEncoding.DecodeString(authKeyB64)
	if err != nil || len(key) == 0 {
		return false
	}
	proof, err := base64.RawURLEncoding.DecodeString(proofB64)
	if err != nil || len(proof) == 0 {
		return false
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(message)
	return hmac.Equal(mac.Sum(nil), proof)
}

func (s *AuthStore) sealSecret(kind, id, plain string) (string, error) {
	if plain == "" || s.aead == nil {
		return plain, nil
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ct := s.aead.Seal(nil, nonce, []byte(plain), []byte("revaulter-v2|"+kind+"|"+id))
	return "enc:" + base64.RawURLEncoding.EncodeToString(nonce) + "." + base64.RawURLEncoding.EncodeToString(ct), nil
}

func (s *AuthStore) openSecret(kind, id, stored string) (string, error) {
	if stored == "" || s.aead == nil || !strings.HasPrefix(stored, "enc:") {
		return stored, nil
	}
	rest := strings.TrimPrefix(stored, "enc:")
	parts := strings.SplitN(rest, ".", 2)
	if len(parts) != 2 {
		return "", errors.New("invalid encrypted secret format")
	}
	nonce, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", err
	}
	ct, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", err
	}
	plain, err := s.aead.Open(nil, nonce, ct, []byte("revaulter-v2|"+kind+"|"+id))
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

func isIgnorableSQLiteMigrationError(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(strings.ToLower(err.Error()), "duplicate column name")
}

func isIgnorablePostgresMigrationError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "already exists") || strings.Contains(msg, "duplicate column")
}
