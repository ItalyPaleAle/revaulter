package v2db

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/italypaleale/go-sql-utils/migrations"
	pgmigrations "github.com/italypaleale/go-sql-utils/migrations/postgres"
	sqlitemigrations "github.com/italypaleale/go-sql-utils/migrations/sqlite"
	"github.com/jackc/pgx/v5"

	"github.com/italypaleale/revaulter/pkg/protocolv2"
)

type V2RequestStatus string

const (
	V2RequestStatusPending   V2RequestStatus = "pending"
	V2RequestStatusCompleted V2RequestStatus = "completed"
	V2RequestStatusCanceled  V2RequestStatus = "canceled"
	V2RequestStatusExpired   V2RequestStatus = "expired"
)

type V2RequestRecord struct {
	State       string
	Status      V2RequestStatus
	Operation   string
	TargetUser  string
	KeyLabel    string
	Algorithm   string
	RequestorIP string
	Note        string
	CreatedAt   time.Time
	ExpiresAt   time.Time
	UpdatedAt   time.Time

	RequestBody      protocolv2.RequestCreateBody
	ResponseEnvelope *protocolv2.ResponseEnvelope
}

type V2RequestListItem struct {
	State      string `json:"state"`
	Status     string `json:"status"`
	Operation  string `json:"operation"`
	TargetUser string `json:"targetUser"`
	KeyLabel   string `json:"keyLabel"`
	Algorithm  string `json:"algorithm"`
	Requestor  string `json:"requestor,omitempty"`
	Date       int64  `json:"date"`
	Expiry     int64  `json:"expiry"`
	Note       string `json:"note,omitempty"`
}

type CreateRequestInput struct {
	State       string
	Operation   string
	RequestorIP string
	CreatedAt   time.Time
	ExpiresAt   time.Time
	Body        protocolv2.RequestCreateBody
}

type RequestStore struct {
	db   *DB
	aead cipher.AEAD
	log  *slog.Logger
}

func NewRequestStore(ctx context.Context, db *DB, payloadKey []byte, logger *slog.Logger) (*RequestStore, error) {
	if db == nil {
		return nil, errors.New("db is nil")
	}
	if len(payloadKey) != 32 {
		return nil, fmt.Errorf("invalid DB payload key length: got %d, want 32", len(payloadKey))
	}
	block, err := aes.NewCipher(payloadKey)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if logger == nil {
		logger = slog.Default()
	}
	s := &RequestStore{db: db, aead: aead, log: logger}
	if err := s.migrate(ctx); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *RequestStore) migrate(ctx context.Context) error {
	switch s.db.Backend {
	case BackendSQLite:
		m := &sqlitemigrations.Migrations{
			Pool:              s.db.SQLite,
			MetadataTableName: "_revaulter_v2_migrations",
			MetadataKey:       "requests",
		}
		return m.Perform(ctx, []migrations.MigrationFn{
			func(ctx context.Context) error {
				return s.migrationCreateRequestsTableSQLite(ctx, m.GetConn())
			},
		}, s.log)
	case BackendPostgres:
		m := pgmigrations.Migrations{
			DB:                s.db.Postgres,
			MetadataTableName: "_revaulter_v2_migrations",
			MetadataKey:       "requests",
		}
		return m.Perform(ctx, []migrations.MigrationFn{s.migrationCreateRequestsTablePostgres}, s.log)
	default:
		return errors.New("unsupported backend")
	}
}

func (s *RequestStore) migrationCreateRequestsTableSQLite(ctx context.Context, conn *sql.Conn) error {
	if conn == nil {
		return errors.New("sqlite migration connection is nil")
	}
	_, err := conn.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS v2_requests (
			state TEXT PRIMARY KEY,
			status TEXT NOT NULL,
			operation TEXT NOT NULL,
			target_user TEXT NOT NULL,
			key_label TEXT NOT NULL,
			algorithm TEXT NOT NULL,
			requestor_ip TEXT NOT NULL,
			note TEXT NOT NULL,
			created_at INTEGER NOT NULL,
			expires_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL,
			payload_ciphertext BLOB NOT NULL,
			payload_nonce BLOB NOT NULL,
			result_ciphertext BLOB,
			result_nonce BLOB
		)`)
	if err != nil {
		return err
	}
	_, _ = conn.ExecContext(ctx, `CREATE INDEX IF NOT EXISTS idx_v2_requests_status_expires ON v2_requests(status, expires_at)`)
	return nil
}

func (s *RequestStore) migrationCreateRequestsTablePostgres(ctx context.Context) error {
	_, err := s.db.Postgres.Exec(ctx, `CREATE TABLE IF NOT EXISTS v2_requests (
			state text PRIMARY KEY,
			status text NOT NULL,
			operation text NOT NULL,
			target_user text NOT NULL,
			key_label text NOT NULL,
			algorithm text NOT NULL,
			requestor_ip text NOT NULL,
			note text NOT NULL,
			created_at bigint NOT NULL,
			expires_at bigint NOT NULL,
			updated_at bigint NOT NULL,
			payload_ciphertext bytea NOT NULL,
			payload_nonce bytea NOT NULL,
			result_ciphertext bytea,
			result_nonce bytea
		)`)
	if err != nil {
		return err
	}
	_, _ = s.db.Postgres.Exec(ctx, `CREATE INDEX IF NOT EXISTS idx_v2_requests_status_expires ON v2_requests(status, expires_at)`)
	return nil
}

func (s *RequestStore) CreateRequest(ctx context.Context, in CreateRequestInput) error {
	payloadCiphertext, payloadNonce, err := s.sealJSON("request-payload", in.State, in.Body)
	if err != nil {
		return err
	}

	note := in.Body.Note
	now := in.CreatedAt.Unix()
	expires := in.ExpiresAt.Unix()
	switch s.db.Backend {
	case BackendSQLite:
		_, err = s.db.SQLite.ExecContext(ctx, `INSERT INTO v2_requests
			(state, status, operation, target_user, key_label, algorithm, requestor_ip, note, created_at, expires_at, updated_at, payload_ciphertext, payload_nonce)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			in.State, string(V2RequestStatusPending), in.Operation, in.Body.TargetUser, in.Body.KeyLabel, in.Body.Algorithm, in.RequestorIP, note, now, expires, now, payloadCiphertext, payloadNonce)
	case BackendPostgres:
		_, err = s.db.Postgres.Exec(ctx, `INSERT INTO v2_requests
			(state, status, operation, target_user, key_label, algorithm, requestor_ip, note, created_at, expires_at, updated_at, payload_ciphertext, payload_nonce)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
			in.State, string(V2RequestStatusPending), in.Operation, in.Body.TargetUser, in.Body.KeyLabel, in.Body.Algorithm, in.RequestorIP, note, now, expires, now, payloadCiphertext, payloadNonce)
	default:
		err = errors.New("unsupported backend")
	}
	return err
}

func (s *RequestStore) GetRequest(ctx context.Context, state string) (*V2RequestRecord, error) {
	rec, err := s.getRequestRaw(ctx, state)
	if err != nil || rec == nil {
		return rec, err
	}
	if rec.Status == V2RequestStatusPending && rec.ExpiresAt.Before(time.Now()) {
		_ = s.MarkExpired(ctx, state)
		return s.getRequestRaw(ctx, state)
	}
	return rec, nil
}

func (s *RequestStore) getRequestRaw(ctx context.Context, state string) (*V2RequestRecord, error) {
	type rowT struct {
		State, Status, Operation, TargetUser, KeyLabel, Algorithm, RequestorIP, Note string
		CreatedAt, ExpiresAt, UpdatedAt                                              int64
		PayloadCiphertext, PayloadNonce                                              []byte
		ResultCiphertext, ResultNonce                                                []byte
	}
	var row rowT
	var err error
	switch s.db.Backend {
	case BackendSQLite:
		err = s.db.SQLite.QueryRowContext(ctx, `SELECT state,status,operation,target_user,key_label,algorithm,requestor_ip,note,created_at,expires_at,updated_at,payload_ciphertext,payload_nonce,result_ciphertext,result_nonce FROM v2_requests WHERE state = ?`, state).
			Scan(&row.State, &row.Status, &row.Operation, &row.TargetUser, &row.KeyLabel, &row.Algorithm, &row.RequestorIP, &row.Note, &row.CreatedAt, &row.ExpiresAt, &row.UpdatedAt, &row.PayloadCiphertext, &row.PayloadNonce, &row.ResultCiphertext, &row.ResultNonce)
	case BackendPostgres:
		err = s.db.Postgres.QueryRow(ctx, `SELECT state,status,operation,target_user,key_label,algorithm,requestor_ip,note,created_at,expires_at,updated_at,payload_ciphertext,payload_nonce,result_ciphertext,result_nonce FROM v2_requests WHERE state = $1`, state).
			Scan(&row.State, &row.Status, &row.Operation, &row.TargetUser, &row.KeyLabel, &row.Algorithm, &row.RequestorIP, &row.Note, &row.CreatedAt, &row.ExpiresAt, &row.UpdatedAt, &row.PayloadCiphertext, &row.PayloadNonce, &row.ResultCiphertext, &row.ResultNonce)
	default:
		return nil, errors.New("unsupported backend")
	}
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}

	var body protocolv2.RequestCreateBody
	if err = s.openJSON("request-payload", row.State, row.PayloadCiphertext, row.PayloadNonce, &body); err != nil {
		return nil, err
	}
	rec := &V2RequestRecord{
		State:       row.State,
		Status:      V2RequestStatus(row.Status),
		Operation:   row.Operation,
		TargetUser:  row.TargetUser,
		KeyLabel:    row.KeyLabel,
		Algorithm:   row.Algorithm,
		RequestorIP: row.RequestorIP,
		Note:        row.Note,
		CreatedAt:   time.Unix(row.CreatedAt, 0),
		ExpiresAt:   time.Unix(row.ExpiresAt, 0),
		UpdatedAt:   time.Unix(row.UpdatedAt, 0),
		RequestBody: body,
	}
	if len(row.ResultCiphertext) > 0 && len(row.ResultNonce) > 0 {
		var env protocolv2.ResponseEnvelope
		if err = s.openJSON("request-result", row.State, row.ResultCiphertext, row.ResultNonce, &env); err != nil {
			return nil, err
		}
		rec.ResponseEnvelope = &env
	}
	return rec, nil
}

func (s *RequestStore) ListPending(ctx context.Context) ([]V2RequestListItem, error) {
	_ = s.ExpirePending(ctx, time.Now())
	var out []V2RequestListItem
	switch s.db.Backend {
	case BackendSQLite:
		rows, err := s.db.SQLite.QueryContext(ctx, `SELECT state,status,operation,target_user,key_label,algorithm,requestor_ip,note,created_at,expires_at FROM v2_requests WHERE status = ? ORDER BY created_at ASC`, string(V2RequestStatusPending))
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		for rows.Next() {
			var item V2RequestListItem
			if err := rows.Scan(&item.State, &item.Status, &item.Operation, &item.TargetUser, &item.KeyLabel, &item.Algorithm, &item.Requestor, &item.Note, &item.Date, &item.Expiry); err != nil {
				return nil, err
			}
			out = append(out, item)
		}
		return out, rows.Err()
	case BackendPostgres:
		rows, err := s.db.Postgres.Query(ctx, `SELECT state,status,operation,target_user,key_label,algorithm,requestor_ip,note,created_at,expires_at FROM v2_requests WHERE status = $1 ORDER BY created_at ASC`, string(V2RequestStatusPending))
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		for rows.Next() {
			var item V2RequestListItem
			if err := rows.Scan(&item.State, &item.Status, &item.Operation, &item.TargetUser, &item.KeyLabel, &item.Algorithm, &item.Requestor, &item.Note, &item.Date, &item.Expiry); err != nil {
				return nil, err
			}
			out = append(out, item)
		}
		return out, rows.Err()
	default:
		return nil, errors.New("unsupported backend")
	}
}

func (s *RequestStore) CompleteRequest(ctx context.Context, state string, env protocolv2.ResponseEnvelope) (bool, error) {
	ct, nonce, err := s.sealJSON("request-result", state, env)
	if err != nil {
		return false, err
	}
	now := time.Now().Unix()
	switch s.db.Backend {
	case BackendSQLite:
		res, err := s.db.SQLite.ExecContext(ctx, `UPDATE v2_requests SET status = ?, updated_at = ?, result_ciphertext = ?, result_nonce = ? WHERE state = ? AND status = ? AND expires_at >= ?`,
			string(V2RequestStatusCompleted), now, ct, nonce, state, string(V2RequestStatusPending), now)
		if err != nil {
			return false, err
		}
		n, _ := res.RowsAffected()
		return n > 0, nil
	case BackendPostgres:
		tag, err := s.db.Postgres.Exec(ctx, `UPDATE v2_requests SET status = $1, updated_at = $2, result_ciphertext = $3, result_nonce = $4 WHERE state = $5 AND status = $6 AND expires_at >= $7`,
			string(V2RequestStatusCompleted), now, ct, nonce, state, string(V2RequestStatusPending), now)
		if err != nil {
			return false, err
		}
		return tag.RowsAffected() > 0, nil
	default:
		return false, errors.New("unsupported backend")
	}
}

func (s *RequestStore) CancelRequest(ctx context.Context, state string) (bool, error) {
	now := time.Now().Unix()
	switch s.db.Backend {
	case BackendSQLite:
		res, err := s.db.SQLite.ExecContext(ctx, `UPDATE v2_requests SET status = ?, updated_at = ? WHERE state = ? AND status = ?`, string(V2RequestStatusCanceled), now, state, string(V2RequestStatusPending))
		if err != nil {
			return false, err
		}
		n, _ := res.RowsAffected()
		return n > 0, nil
	case BackendPostgres:
		tag, err := s.db.Postgres.Exec(ctx, `UPDATE v2_requests SET status = $1, updated_at = $2 WHERE state = $3 AND status = $4`, string(V2RequestStatusCanceled), now, state, string(V2RequestStatusPending))
		if err != nil {
			return false, err
		}
		return tag.RowsAffected() > 0, nil
	default:
		return false, errors.New("unsupported backend")
	}
}

func (s *RequestStore) MarkExpired(ctx context.Context, state string) error {
	now := time.Now().Unix()
	switch s.db.Backend {
	case BackendSQLite:
		_, err := s.db.SQLite.ExecContext(ctx, `UPDATE v2_requests SET status = ?, updated_at = ? WHERE state = ? AND status = ? AND expires_at < ?`,
			string(V2RequestStatusExpired), now, state, string(V2RequestStatusPending), now)
		return err
	case BackendPostgres:
		_, err := s.db.Postgres.Exec(ctx, `UPDATE v2_requests SET status = $1, updated_at = $2 WHERE state = $3 AND status = $4 AND expires_at < $5`,
			string(V2RequestStatusExpired), now, state, string(V2RequestStatusPending), now)
		return err
	default:
		return errors.New("unsupported backend")
	}
}

func (s *RequestStore) ExpirePending(ctx context.Context, now time.Time) error {
	n := now.Unix()
	switch s.db.Backend {
	case BackendSQLite:
		_, err := s.db.SQLite.ExecContext(ctx, `UPDATE v2_requests SET status = ?, updated_at = ? WHERE status = ? AND expires_at < ?`,
			string(V2RequestStatusExpired), n, string(V2RequestStatusPending), n)
		return err
	case BackendPostgres:
		_, err := s.db.Postgres.Exec(ctx, `UPDATE v2_requests SET status = $1, updated_at = $2 WHERE status = $3 AND expires_at < $4`,
			string(V2RequestStatusExpired), n, string(V2RequestStatusPending), n)
		return err
	default:
		return errors.New("unsupported backend")
	}
}

func (s *RequestStore) ExpirePendingAndReturnStates(ctx context.Context, now time.Time) ([]string, error) {
	n := now.Unix()
	switch s.db.Backend {
	case BackendSQLite:
		rows, err := s.db.SQLite.QueryContext(ctx, `SELECT state FROM v2_requests WHERE status = ? AND expires_at < ?`,
			string(V2RequestStatusPending), n)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var states []string
		for rows.Next() {
			var st string
			if err := rows.Scan(&st); err != nil {
				return nil, err
			}
			states = append(states, st)
		}
		if err := rows.Err(); err != nil {
			return nil, err
		}
		if len(states) == 0 {
			return nil, nil
		}
		if _, err := s.db.SQLite.ExecContext(ctx, `UPDATE v2_requests SET status = ?, updated_at = ? WHERE status = ? AND expires_at < ?`,
			string(V2RequestStatusExpired), n, string(V2RequestStatusPending), n); err != nil {
			return nil, err
		}
		return states, nil
	case BackendPostgres:
		rows, err := s.db.Postgres.Query(ctx, `UPDATE v2_requests SET status = $1, updated_at = $2 WHERE status = $3 AND expires_at < $4 RETURNING state`,
			string(V2RequestStatusExpired), n, string(V2RequestStatusPending), n)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var states []string
		for rows.Next() {
			var st string
			if err := rows.Scan(&st); err != nil {
				return nil, err
			}
			states = append(states, st)
		}
		return states, rows.Err()
	default:
		return nil, errors.New("unsupported backend")
	}
}

func (s *RequestStore) sealJSON(kind, id string, v any) (ciphertext []byte, nonce []byte, err error) {
	plain, err := json.Marshal(v)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, s.aead.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}
	aad := []byte("revaulter-v2|" + kind + "|" + id)
	ciphertext = s.aead.Seal(nil, nonce, plain, aad)
	return ciphertext, nonce, nil
}

func (s *RequestStore) openJSON(kind, id string, ciphertext, nonce []byte, out any) error {
	aad := []byte("revaulter-v2|" + kind + "|" + id)
	plain, err := s.aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return err
	}
	return json.Unmarshal(plain, out)
}
