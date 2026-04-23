package db

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/italypaleale/go-sql-utils/adapter"

	"github.com/italypaleale/revaulter/pkg/protocolv2"
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
}

type RequestStore struct {
	db adapter.Querier
}

func NewRequestStore(db adapter.Querier) (*RequestStore, error) {
	if db == nil {
		return nil, errors.New("db is nil")
	}

	s := &RequestStore{
		db: db,
	}

	return s, nil
}

func (s *RequestStore) CreateRequest(ctx context.Context, in CreateRequestInput) error {
	now := in.CreatedAt.Unix()
	expires := in.ExpiresAt.Unix()
	_, err := s.db.Exec(ctx,
		`INSERT INTO v2_requests
			(state, status, operation, user_id, key_label, algorithm, requestor_ip, note, created_at, expires_at, updated_at, encrypted_request)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
		in.State, string(V2RequestStatusPending), in.Operation, in.UserID, in.KeyLabel, in.Algorithm, in.RequestorIP, in.Note, now, expires, now, in.EncryptedRequest,
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

func (s *RequestStore) GetAndDeleteTerminalRequest(ctx context.Context, state string) (*V2RequestRecord, error) {
	now := time.Now().Unix()
	var (
		stateOut, status, operation, userID    string
		keyLabel, algorithm, requestorIP, note string
		createdAt, expiresAt, updatedAt        int64
		encryptedRequest, encryptedResult      string
	)
	err := s.db.QueryRow(ctx,
		`DELETE FROM v2_requests
			WHERE state = $1 AND (status != $2 OR expires_at < $3)
			RETURNING
				state,
				CASE WHEN status = $2 AND expires_at < $3 THEN $4 ELSE status END,
				operation,
				user_id,
				key_label,
				algorithm,
				requestor_ip,
				note,
				created_at,
				expires_at,
				CASE WHEN status = $2 AND expires_at < $3 THEN $3 ELSE updated_at END,
				encrypted_request,
				encrypted_result`,
		state,
		string(V2RequestStatusPending),
		now,
		string(V2RequestStatusExpired),
	).Scan(
		&stateOut, &status, &operation, &userID, &keyLabel, &algorithm, &requestorIP, &note,
		&createdAt, &expiresAt, &updatedAt, &encryptedRequest, &encryptedResult,
	)
	if s.db.IsNoRowsError(err) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}

	rec := &V2RequestRecord{
		State:            stateOut,
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

func (s *RequestStore) ListPending(ctx context.Context) ([]V2RequestListItem, error) {
	_ = s.ExpirePending(ctx, time.Now())
	var out []V2RequestListItem
	rows, err := s.db.Query(ctx,
		`SELECT state,status,operation,user_id,key_label,algorithm,requestor_ip,note,created_at,expires_at FROM v2_requests WHERE status = $1 ORDER BY created_at ASC`,
		string(V2RequestStatusPending),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

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
func (s *RequestStore) CancelRequest(ctx context.Context, state, userID string) (*V2RequestRecord, error) {
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

// MarkExpired atomically transitions a pending, past-deadline request to the expired state
// Returns the updated record on a successful transition, or (nil, nil) if no row matched (unknown state, not pending, or not yet past deadline)
func (s *RequestStore) MarkExpired(ctx context.Context, state string) (*V2RequestRecord, error) {
	now := time.Now().Unix()
	rec, err := scanRequestRecord(
		s.db.QueryRow(ctx,
			`UPDATE v2_requests SET status = $1, updated_at = $2
				WHERE state = $3 AND status = $4 AND expires_at < $5
				RETURNING `+requestColumns,
			string(V2RequestStatusExpired), now, state, string(V2RequestStatusPending), now,
		),
	)
	if s.db.IsNoRowsError(err) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return rec, nil
}

func (s *RequestStore) ExpirePending(ctx context.Context, now time.Time) error {
	n := now.Unix()
	_, err := s.db.Exec(ctx,
		`UPDATE v2_requests SET status = $1, updated_at = $2 WHERE status = $3 AND expires_at < $4`,
		string(V2RequestStatusExpired), n, string(V2RequestStatusPending), n,
	)
	return err
}

// CleanupOldRecords deletes non-pending requests that expired more than 10 minutes ago.
func (s *RequestStore) CleanupOldRecords(ctx context.Context, now time.Time) (int64, error) {
	cutoff := now.Add(-10 * time.Minute).Unix()
	affected, err := s.db.Exec(ctx,
		`DELETE FROM v2_requests WHERE status != $1 AND expires_at < $2`,
		string(V2RequestStatusPending), cutoff)
	if err != nil {
		return 0, err
	}
	return affected, nil
}

func (s *RequestStore) DeleteTerminalRequest(ctx context.Context, state string, cutoff *time.Time) error {
	query := `DELETE FROM v2_requests WHERE state = $1 AND status != $2`
	args := []any{state, string(V2RequestStatusPending)}
	if cutoff != nil {
		expiresBefore := cutoff.Add(-10 * time.Minute).Unix()
		query += ` AND expires_at < $3`
		args = append(args, expiresBefore)
	}

	_, err := s.db.Exec(ctx, query, args...)
	return err
}

// requestRowScanner is implemented by *sql.Row — used by scanRequestRecord so the same column list is used from SELECT and UPDATE ... RETURNING calls
type requestRowScanner interface {
	Scan(dest ...any) error
}

const requestColumns = `state, status, operation, user_id, key_label, algorithm, requestor_ip, note, created_at, expires_at, updated_at, encrypted_request, encrypted_result`

func scanRequestRecord(scanner requestRowScanner) (*V2RequestRecord, error) {
	var (
		state, status, operation, userID, keyLabel, algorithm, requestorIP, note string
		createdAt, expiresAt, updatedAt                                          int64
		encryptedRequest, encryptedResult                                        string
	)
	err := scanner.Scan(
		&state, &status, &operation, &userID, &keyLabel, &algorithm, &requestorIP, &note, &createdAt, &expiresAt, &updatedAt, &encryptedRequest, &encryptedResult,
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
