package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/italypaleale/go-sql-utils/adapter"

	"github.com/italypaleale/revaulter/internal/protocolv2"
)

type V2RequestStatus string

const (
	V2RequestStatusPending   V2RequestStatus = "pending"
	V2RequestStatusCompleted V2RequestStatus = "completed"
	V2RequestStatusCanceled  V2RequestStatus = "canceled"
	V2RequestStatusExpired   V2RequestStatus = "expired"
)

// ErrRequestNotModifiable is returned when the atomic mutation on v2_requests matched no row
// It collapses three cases — unknown state, state belonging to another user, or a row that is no longer pending (already completed/canceled/expired) — so callers cannot probe for another user's requests
var ErrRequestNotModifiable = errors.New("request cannot be modified")

type V2RequestRecord struct {
	State       string
	Status      V2RequestStatus
	Operation   string
	UserID      string
	KeyLabel    string
	Algorithm   string
	RequestorIP string
	Note        string
	CreatedAt   time.Time
	ExpiresAt   time.Time
	UpdatedAt   time.Time

	// EncryptedRequest is the E2EE envelope JSON (opaque to the server).
	EncryptedRequest string
	// ResponseEnvelope is the E2EE response envelope JSON (opaque to the server).
	ResponseEnvelope *protocolv2.ResponseEnvelope
	// ResultTokenHash is the SHA-256 of the result token returned when the request was created
	ResultTokenHash string
}

type V2RequestListItem struct {
	State     string `json:"state"`
	Status    string `json:"status"`
	Operation string `json:"operation"`
	UserID    string `json:"userId"`
	KeyLabel  string `json:"keyLabel"`
	Algorithm string `json:"algorithm"`
	Requestor string `json:"requestor,omitempty"`
	Date      int64  `json:"date"`
	Expiry    int64  `json:"expiry"`
	Note      string `json:"note,omitempty"`
}

type CreateRequestInput struct {
	State       string
	UserID      string
	Operation   string
	RequestorIP string
	KeyLabel    string
	Algorithm   string
	Note        string
	CreatedAt   time.Time
	ExpiresAt   time.Time
	// EncryptedRequest is the JSON-serialized RequestEncEnvelope.
	EncryptedRequest string
	// ResultTokenHash is the SHA-256 of the result token returned to the client
	ResultTokenHash string
}

// requestTxTimeout is the timeout for the transactions RequestStore starts on its own
const requestTxTimeout = 30 * time.Second

type RequestStore struct {
	db   adapter.Querier
	kind BackendKind

	// conn is set when the store is not in a transaction
	conn *DB
}

func NewRequestStore(db adapter.Querier, kind BackendKind) (*RequestStore, error) {
	if db == nil {
		return nil, errors.New("db is nil")
	}

	s := &RequestStore{
		db:   db,
		kind: kind,
	}

	return s, nil
}

// inTransaction runs fn with a store in a transaction
func (s *RequestStore) inTransaction(ctx context.Context, fn func(ctx context.Context, rs *RequestStore) error) error {
	if s.conn == nil {
		return fn(ctx, s)
	}

	_, err := ExecuteInTransaction(ctx, s.conn, requestTxTimeout, func(ctx context.Context, tx *DbTx) (struct{}, error) {
		return struct{}{}, fn(ctx, tx.RequestStore())
	})
	return err
}

func (s *RequestStore) CreateRequest(ctx context.Context, in CreateRequestInput) error {
	now := in.CreatedAt.Unix()
	expires := in.ExpiresAt.Unix()
	_, err := s.db.Exec(ctx,
		`INSERT INTO v2_requests
			(state, status, operation, user_id, key_label, algorithm, requestor_ip, note, created_at, expires_at, updated_at, encrypted_request, result_token_hash)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
		in.State, string(V2RequestStatusPending), in.Operation, in.UserID, in.KeyLabel, in.Algorithm, in.RequestorIP, in.Note, now, expires, now, in.EncryptedRequest, in.ResultTokenHash,
	)
	return err
}

func (s *RequestStore) GetRequest(ctx context.Context, state string) (*V2RequestRecord, error) {
	rec, err := s.getRequestRaw(ctx, state)
	if err != nil || rec == nil {
		return rec, err
	}

	if rec.Status == V2RequestStatusPending && rec.ExpiresAt.Before(time.Now()) {
		expired, err := s.MarkExpired(ctx, state)
		if err != nil {
			return nil, err
		}
		if expired != nil {
			return expired, nil
		}
		// A concurrent writer changed the row between our read and the UPDATE; re-read to reflect the authoritative state
		return s.getRequestRaw(ctx, state)
	}

	return rec, nil
}

// GetAndDeleteTerminalRequest deletes a request in a terminal state and returns it
// Returns (nil, nil) if the request doesn't exist or is still pending
func (s *RequestStore) GetAndDeleteTerminalRequest(ctx context.Context, state string) (rec *V2RequestRecord, err error) {
	err = s.inTransaction(ctx, func(ctx context.Context, rs *RequestStore) error {
		_, rErr := rs.markExpired(ctx, state, time.Now())
		if rErr != nil {
			return rErr
		}

		rec, rErr = scanRequestRecord(
			rs.db.QueryRow(ctx,
				`DELETE FROM v2_requests
					WHERE state = $1 AND status != $2
					RETURNING `+requestColumns,
				state, string(V2RequestStatusPending),
			),
		)
		if rs.db.IsNoRowsError(rErr) {
			rec = nil
			return nil
		}
		return rErr
	})
	if err != nil {
		return nil, err
	}

	return rec, nil
}

func (s *RequestStore) getRequestRaw(ctx context.Context, state string) (*V2RequestRecord, error) {
	rec, err := scanRequestRecord(
		s.db.QueryRow(ctx,
			`SELECT `+requestColumns+` FROM v2_requests WHERE state = $1`,
			state,
		),
	)
	if s.db.IsNoRowsError(err) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return rec, nil
}

// ListPending returns all pending requests
// The userId parameter is optional and it allows filtering by user
func (s *RequestStore) ListPending(ctx context.Context, userID string) ([]V2RequestListItem, error) {
	// Opportunistically expire pending requests (no matter the user)
	_, _ = s.ExpirePending(ctx, time.Now())

	// Add the user clause if needed
	params := make([]any, 1, 2)
	params[0] = string(V2RequestStatusPending)
	var userClause string
	if userID != "" {
		userClause = " AND user_id = $2"
		params = append(params, userID)
	}

	// List all pending items
	rows, err := s.db.Query(ctx,
		`SELECT state, status, operation, user_id, key_label, algorithm, requestor_ip, note, created_at, expires_at FROM v2_requests
		WHERE status = $1 `+userClause+`
		ORDER BY created_at ASC`,
		params...,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// Scan records
	var out []V2RequestListItem
	for rows.Next() {
		var item V2RequestListItem
		err = rows.Scan(&item.State, &item.Status, &item.Operation, &item.UserID, &item.KeyLabel, &item.Algorithm, &item.Requestor, &item.Note, &item.Date, &item.Expiry)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}

	return out, rows.Err()
}

// CompleteRequest atomically transitions a pending, non-expired request owned by userID to completed and stores the response envelope
// Returns the updated record on success
// Returns ErrRequestNotModifiable if no row matched: unknown state, different owner, or already in a terminal/expired state
func (s *RequestStore) CompleteRequest(ctx context.Context, state, userID string, env protocolv2.ResponseEnvelope) (*V2RequestRecord, error) {
	envJSON, err := json.Marshal(env)
	if err != nil {
		return nil, err
	}

	now := time.Now().Unix()
	rec, err := scanRequestRecord(
		s.db.QueryRow(ctx,
			`UPDATE v2_requests SET status = $1, updated_at = $2, encrypted_result = $3
				WHERE state = $4 AND user_id = $5 AND status = $6 AND expires_at >= $7
				RETURNING `+requestColumns,
			string(V2RequestStatusCompleted), now, string(envJSON), state, userID, string(V2RequestStatusPending), now,
		),
	)
	if s.db.IsNoRowsError(err) {
		return nil, ErrRequestNotModifiable
	} else if err != nil {
		return nil, err
	}
	return rec, nil
}

// CancelRequest atomically transitions a pending request owned by userID to canceled
// Returns the updated record on success, or ErrRequestNotModifiable if no row matched (same collapsed-cases rationale as CompleteRequest)
func (s *RequestStore) CancelRequest(ctx context.Context, state string, userID string) (*V2RequestRecord, error) {
	now := time.Now().Unix()
	rec, err := scanRequestRecord(
		s.db.QueryRow(ctx,
			`UPDATE v2_requests SET status = $1, updated_at = $2
				WHERE state = $3 AND user_id = $4 AND status = $5
				RETURNING `+requestColumns,
			string(V2RequestStatusCanceled), now, state, userID, string(V2RequestStatusPending),
		),
	)
	if s.db.IsNoRowsError(err) {
		return nil, ErrRequestNotModifiable
	} else if err != nil {
		return nil, err
	}
	return rec, nil
}

// MarkExpired atomically transitions a pending, past-deadline request to the expired state, and records the expiry in the audit log
// Returns the updated record on a successful transition, or (nil, nil) if no row matched (unknown state, not pending, or not yet past deadline)
func (s *RequestStore) MarkExpired(ctx context.Context, state string) (rec *V2RequestRecord, err error) {
	err = s.inTransaction(ctx, func(ctx context.Context, rs *RequestStore) error {
		var rErr error
		rec, rErr = rs.markExpired(ctx, state, time.Now())
		return rErr
	})
	if err != nil {
		return nil, err
	}

	return rec, nil
}

// markExpired is the implementation of MarkExpired
// It must be invoked on a store in a transaction
func (s *RequestStore) markExpired(ctx context.Context, state string, now time.Time) (*V2RequestRecord, error) {
	n := now.Unix()
	rec, err := scanRequestRecord(
		s.db.QueryRow(ctx,
			`UPDATE v2_requests SET status = $1, updated_at = $2
				WHERE state = $3 AND status = $4 AND expires_at < $5
				RETURNING `+requestColumns,
			string(V2RequestStatusExpired), n, state, string(V2RequestStatusPending), n,
		),
	)
	if s.db.IsNoRowsError(err) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}

	err = s.insertExpireAuditEvents(ctx, rec)
	if err != nil {
		return nil, err
	}

	return rec, nil
}

// ExpirePending transitions all pending, past-deadline requests to the expired state, and records each expiry in the audit log
// Returns the records that were expired
func (s *RequestStore) ExpirePending(ctx context.Context, now time.Time) (expired []*V2RequestRecord, err error) {
	err = s.inTransaction(ctx, func(ctx context.Context, rs *RequestStore) error {
		var rErr error
		expired, rErr = rs.expirePending(ctx, now)
		return rErr
	})
	if err != nil {
		return nil, err
	}

	return expired, nil
}

// expirePending is the implementation of ExpirePending
// It must be invoked on a store in a transaction
func (s *RequestStore) expirePending(ctx context.Context, now time.Time) ([]*V2RequestRecord, error) {
	n := now.Unix()
	rows, err := s.db.Query(ctx,
		`UPDATE v2_requests SET status = $1, updated_at = $2
			WHERE status = $3 AND expires_at < $4
			RETURNING `+requestColumns,
		string(V2RequestStatusExpired), n, string(V2RequestStatusPending), n,
	)
	if err != nil {
		return nil, err
	}

	// Read all rows before writing the audit events, as the connection can't run other queries while the result set is open
	expired, err := scanRequestRecords(rows)
	if err != nil {
		return nil, err
	}

	err = s.insertExpireAuditEvents(ctx, expired...)
	if err != nil {
		return nil, err
	}

	return expired, nil
}

// insertExpireAuditEvents records the expiry of requests in the audit log
// Expiry is performed by the system, and each request's owner is both the actor and the target
func (s *RequestStore) insertExpireAuditEvents(ctx context.Context, recs ...*V2RequestRecord) error {
	as, err := NewAuditStore(s.db, s.kind)
	if err != nil {
		return err
	}

	events := make([]AuditEventInput, len(recs))
	for i, rec := range recs {
		events[i] = AuditEventInput{
			EventType:    AuditRequestExpire,
			Outcome:      AuditOutcomeSuccess,
			AuthMethod:   AuditAuthMethodSystem,
			ActorUserID:  &rec.UserID,
			TargetUserID: &rec.UserID,
			RequestState: &rec.State,
			Metadata:     RequestAuditMetadata(rec.Operation, rec.Algorithm, rec.KeyLabel, rec.Note),
		}
	}

	err = as.InsertMany(ctx, events)
	if err != nil {
		return fmt.Errorf("failed to write audit events for request expiry: %w", err)
	}

	return nil
}

// CleanupOldRecords deletes non-pending requests that expired more than 10 minutes ago.
func (s *RequestStore) CleanupOldRecords(ctx context.Context, now time.Time) (int64, error) {
	cutoff := now.Add(-10 * time.Minute).Unix()
	affected, err := s.db.Exec(ctx,
		"DELETE FROM v2_requests WHERE status != $1 AND expires_at < $2",
		string(V2RequestStatusPending), cutoff,
	)
	if err != nil {
		return 0, err
	}
	return affected, nil
}

func (s *RequestStore) DeleteTerminalRequest(ctx context.Context, state string, cutoff *time.Time) error {
	query := "DELETE FROM v2_requests WHERE state = $1 AND status != $2"
	args := []any{state, string(V2RequestStatusPending)}
	if cutoff != nil {
		expiresBefore := cutoff.Add(-10 * time.Minute).Unix()
		query += ` AND expires_at < $3`
		args = append(args, expiresBefore)
	}

	_, err := s.db.Exec(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("error deleting request: %w", err)
	}

	return err
}

// GetResultTokenAndOwner returns the hash of the request's result token, and the user who owns the request, in a single query
// It returns a nil user if the request doesn't exist
// Unlike GetRequest, it doesn't mark past-deadline requests as expired
func (s *RequestStore) GetResultTokenAndOwner(ctx context.Context, state string) (resultTokenHash string, owner *User, err error) {
	owner, err = scanUser(
		s.db.QueryRow(ctx,
			`SELECT `+userColumnsAliasU+`, r.result_token_hash
				FROM v2_requests r
				JOIN v2_users u ON u.id = r.user_id
				WHERE r.state = $1`,
			state,
		),
		&resultTokenHash,
	)
	if s.db.IsNoRowsError(err) {
		return "", nil, nil
	} else if err != nil {
		return "", nil, err
	}

	return resultTokenHash, owner, nil
}

// requestRowScanner is implemented by *sql.Row — used by scanRequestRecord so the same column list is used from SELECT and UPDATE ... RETURNING calls
type requestRowScanner interface {
	Scan(dest ...any) error
}

// requestRowsScanner is implemented by the result of Query
type requestRowsScanner interface {
	requestRowScanner

	Next() bool
	Err() error
	Close() error
}

// scanRequestRecords reads all records from rows, then closes it
func scanRequestRecords(rows requestRowsScanner) ([]*V2RequestRecord, error) {
	defer rows.Close()

	var out []*V2RequestRecord
	for rows.Next() {
		rec, err := scanRequestRecord(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}

	return out, rows.Err()
}

const requestColumns = `state, status, operation, user_id, key_label, algorithm, requestor_ip, note, created_at, expires_at, updated_at, encrypted_request, encrypted_result, result_token_hash`

func scanRequestRecord(scanner requestRowScanner) (*V2RequestRecord, error) {
	var (
		state, status, operation, userID, keyLabel, algorithm, requestorIP, note string
		createdAt, expiresAt, updatedAt                                          int64
		encryptedRequest, encryptedResult, resultTokenHash                       string
	)
	err := scanner.Scan(
		&state, &status, &operation, &userID, &keyLabel, &algorithm, &requestorIP, &note, &createdAt, &expiresAt, &updatedAt, &encryptedRequest, &encryptedResult, &resultTokenHash,
	)
	if err != nil {
		return nil, err
	}

	rec := &V2RequestRecord{
		State:            state,
		Status:           V2RequestStatus(status),
		Operation:        operation,
		UserID:           userID,
		KeyLabel:         keyLabel,
		Algorithm:        algorithm,
		RequestorIP:      requestorIP,
		Note:             note,
		CreatedAt:        time.Unix(createdAt, 0),
		ExpiresAt:        time.Unix(expiresAt, 0),
		UpdatedAt:        time.Unix(updatedAt, 0),
		EncryptedRequest: encryptedRequest,
		ResultTokenHash:  resultTokenHash,
	}
	if encryptedResult != "" {
		var env protocolv2.ResponseEnvelope
		err = json.Unmarshal([]byte(encryptedResult), &env)
		if err != nil {
			return nil, err
		}
		rec.ResponseEnvelope = &env
	}
	return rec, nil
}
