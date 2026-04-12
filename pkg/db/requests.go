package db

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"time"

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
	db  *DB
	log *slog.Logger
}

func NewRequestStore(db *DB, logger *slog.Logger) (*RequestStore, error) {
	if db == nil {
		return nil, errors.New("db is nil")
	}

	if logger == nil {
		logger = slog.Default()
	}
	s := &RequestStore{
		db:  db,
		log: logger,
	}

	return s, nil
}

func (s *RequestStore) CreateRequest(ctx context.Context, in CreateRequestInput) error {
	now := in.CreatedAt.Unix()
	expires := in.ExpiresAt.Unix()
	_, err := s.db.db.Exec(ctx,
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
		_ = s.MarkExpired(ctx, state)
		return s.getRequestRaw(ctx, state)
	}
	return rec, nil
}

func (s *RequestStore) getRequestRaw(ctx context.Context, state string) (*V2RequestRecord, error) {
	type rowT struct {
		State, Status, Operation, UserID, KeyLabel, Algorithm, RequestorIP, Note string
		CreatedAt, ExpiresAt, UpdatedAt                                          int64
		EncryptedRequest                                                         string
		EncryptedResult                                                          string
	}
	var row rowT

	err := s.db.db.
		QueryRow(ctx,
			`SELECT state, status, operation, user_id, key_label, algorithm, requestor_ip, note, created_at, expires_at, updated_at, encrypted_request, encrypted_result FROM v2_requests WHERE state = $1`,
			state,
		).
		Scan(
			&row.State, &row.Status, &row.Operation, &row.UserID, &row.KeyLabel, &row.Algorithm, &row.RequestorIP, &row.Note, &row.CreatedAt, &row.ExpiresAt, &row.UpdatedAt, &row.EncryptedRequest, &row.EncryptedResult,
		)
	if s.db.db.IsNoRowsError(err) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}

	rec := &V2RequestRecord{
		State:            row.State,
		Status:           V2RequestStatus(row.Status),
		Operation:        row.Operation,
		UserID:           row.UserID,
		KeyLabel:         row.KeyLabel,
		Algorithm:        row.Algorithm,
		RequestorIP:      row.RequestorIP,
		Note:             row.Note,
		CreatedAt:        time.Unix(row.CreatedAt, 0),
		ExpiresAt:        time.Unix(row.ExpiresAt, 0),
		UpdatedAt:        time.Unix(row.UpdatedAt, 0),
		EncryptedRequest: row.EncryptedRequest,
	}

	if row.EncryptedResult != "" {
		var env protocolv2.ResponseEnvelope
		err = json.Unmarshal([]byte(row.EncryptedResult), &env)
		if err != nil {
			return nil, err
		}
		rec.ResponseEnvelope = &env
	}
	return rec, nil
}

func (s *RequestStore) ListPending(ctx context.Context) ([]V2RequestListItem, error) {
	_ = s.ExpirePending(ctx, time.Now())
	var out []V2RequestListItem
	rows, err := s.db.db.Query(ctx,
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

func (s *RequestStore) CompleteRequest(ctx context.Context, state string, env protocolv2.ResponseEnvelope) (bool, error) {
	envJSON, err := json.Marshal(env)
	if err != nil {
		return false, err
	}

	now := time.Now().Unix()
	affected, err := s.db.db.Exec(ctx,
		`UPDATE v2_requests SET status = $1, updated_at = $2, encrypted_result = $3 WHERE state = $4 AND status = $5 AND expires_at >= $6`,
		string(V2RequestStatusCompleted), now, string(envJSON), state, string(V2RequestStatusPending), now,
	)
	if err != nil {
		return false, err
	}
	return affected > 0, nil
}

func (s *RequestStore) CancelRequest(ctx context.Context, state string) (bool, error) {
	now := time.Now().Unix()
	affected, err := s.db.db.Exec(ctx,
		`UPDATE v2_requests SET status = $1, updated_at = $2 WHERE state = $3 AND status = $4`,
		string(V2RequestStatusCanceled), now, state, string(V2RequestStatusPending),
	)
	if err != nil {
		return false, err
	}
	return affected > 0, nil
}

func (s *RequestStore) MarkExpired(ctx context.Context, state string) error {
	now := time.Now().Unix()
	_, err := s.db.db.Exec(ctx,
		`UPDATE v2_requests SET status = $1, updated_at = $2 WHERE state = $3 AND status = $4 AND expires_at < $5`,
		string(V2RequestStatusExpired), now, state, string(V2RequestStatusPending), now,
	)
	return err
}

func (s *RequestStore) ExpirePending(ctx context.Context, now time.Time) error {
	n := now.Unix()
	_, err := s.db.db.Exec(ctx,
		`UPDATE v2_requests SET status = $1, updated_at = $2 WHERE status = $3 AND expires_at < $4`,
		string(V2RequestStatusExpired), n, string(V2RequestStatusPending), n,
	)
	return err
}

// ExpiredRequestRef identifies a request row that was just transitioned from pending to expired
type ExpiredRequestRef struct {
	State  string
	UserID string
}

func (s *RequestStore) ExpirePendingAndReturnStates(ctx context.Context, now time.Time) ([]ExpiredRequestRef, error) {
	n := now.Unix()
	rows, err := s.db.db.Query(ctx,
		`UPDATE v2_requests SET status = $1, updated_at = $2 WHERE status = $3 AND expires_at < $4 RETURNING state, user_id`,
		string(V2RequestStatusExpired), n, string(V2RequestStatusPending), n,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var refs []ExpiredRequestRef
	for rows.Next() {
		var ref ExpiredRequestRef
		err = rows.Scan(&ref.State, &ref.UserID)
		if err != nil {
			return nil, err
		}
		refs = append(refs, ref)
	}

	return refs, rows.Err()
}

// CleanupOldRecords deletes non-pending requests that expired more than 10 minutes ago.
func (s *RequestStore) CleanupOldRecords(ctx context.Context, now time.Time) (int64, error) {
	cutoff := now.Add(-10 * time.Minute).Unix()
	affected, err := s.db.db.Exec(ctx,
		`DELETE FROM v2_requests WHERE status != $1 AND expires_at < $2`,
		string(V2RequestStatusPending), cutoff)
	if err != nil {
		return 0, err
	}
	return affected, nil
}
