package db

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/italypaleale/go-sql-utils/adapter"
)

type V2RequestStatus string

const (
	V2RequestStatusPending   V2RequestStatus = "pending"
	V2RequestStatusCompleted V2RequestStatus = "completed"
	V2RequestStatusCanceled  V2RequestStatus = "canceled"
	V2RequestStatusExpired   V2RequestStatus = "expired"
)

// IsTerminal returns true if the status is final, and the request can't change anymore
func (s V2RequestStatus) IsTerminal() bool {
	switch s {
	case V2RequestStatusCompleted, V2RequestStatusCanceled, V2RequestStatusExpired:
		return true
	default:
		return false
	}
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

var (
	// ErrRequestPayloadNotFound is returned when no payload row matches the request and its owner
	ErrRequestPayloadNotFound = errors.New("request payload not found")
	// ErrRequestPayloadConflict is returned when storing a request whose state is already used by another user's request
	ErrRequestPayloadConflict = errors.New("request state is already in use")
)

// RequestPayload contains the encrypted envelopes of a request, and its status
// The request's metadata lives in the revaulter.user actor
// The status here is the one that counts: a transition is recorded here first, together with its audit event, and the actor follows
type RequestPayload struct {
	State     string
	UserID    string
	ExpiresAt time.Time
	Status    V2RequestStatus

	// EncryptedRequest is the E2EE request envelope JSON (opaque to the server)
	EncryptedRequest string
	// EncryptedResult is the E2EE response envelope JSON (opaque to the server)
	// It's empty until the request is confirmed
	EncryptedResult string
}

// RequestPayloadStore stores the encrypted envelopes of requests in the v2_request_payloads table
// The table is never included in backups
type RequestPayloadStore struct {
	db adapter.Querier
}

func NewRequestPayloadStore(db adapter.Querier) (*RequestPayloadStore, error) {
	if db == nil {
		return nil, errors.New("db is nil")
	}

	return &RequestPayloadStore{
		db: db,
	}, nil
}

// RequestPayloadStore returns an instance of RequestPayloadStore
func (db *DB) RequestPayloadStore() *RequestPayloadStore {
	rs, err := NewRequestPayloadStore(db)
	if err != nil {
		// Indicates a development-time error
		panic(err)
	}

	return rs
}

// RequestPayloadStore returns an instance of RequestPayloadStore for the transaction
func (tx *DbTx) RequestPayloadStore() *RequestPayloadStore {
	rs, err := NewRequestPayloadStore(tx)
	if err != nil {
		// Indicates a development-time error
		panic(err)
	}

	return rs
}

// Insert stores the request envelope of a new request, which is pending
// If the request is stored already, for example by an earlier attempt that failed later, it changes nothing, and returns false with the request's status
// It returns ErrRequestPayloadConflict if the state is used by another user's request
func (s *RequestPayloadStore) Insert(ctx context.Context, in RequestPayload) (status V2RequestStatus, created bool, err error) {
	affected, err := s.db.Exec(ctx,
		`INSERT INTO v2_request_payloads (state, user_id, expires_at, encrypted_request, encrypted_result, status)
			VALUES ($1, $2, $3, $4, $5, $6)
			ON CONFLICT (state) DO NOTHING`,
		in.State, in.UserID, in.ExpiresAt.Unix(), in.EncryptedRequest, in.EncryptedResult, string(V2RequestStatusPending),
	)
	if err != nil {
		return "", false, fmt.Errorf("error inserting request payload: %w", err)
	}
	if affected > 0 {
		return V2RequestStatusPending, true, nil
	}

	var userID string
	err = s.db.
		QueryRow(ctx, `SELECT user_id, status FROM v2_request_payloads WHERE state = $1`, in.State).
		Scan(&userID, &status)
	if err != nil {
		return "", false, fmt.Errorf("error reading existing request payload: %w", err)
	}
	if userID != in.UserID {
		return "", false, ErrRequestPayloadConflict
	}

	return status, false, nil
}

// Get returns the envelopes of a request owned by userID
// It returns nil if there's no row for the request and its owner
func (s *RequestPayloadStore) Get(ctx context.Context, state string, userID string) (*RequestPayload, error) {
	var (
		res       RequestPayload
		expiresAt int64
	)
	err := s.db.
		QueryRow(ctx,
			`SELECT state, user_id, expires_at, status, encrypted_request, encrypted_result
				FROM v2_request_payloads
				WHERE state = $1 AND user_id = $2`,
			state, userID,
		).
		Scan(&res.State, &res.UserID, &expiresAt, &res.Status, &res.EncryptedRequest, &res.EncryptedResult)
	if s.db.IsNoRowsError(err) {
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("error reading request payload: %w", err)
	}

	res.ExpiresAt = time.Unix(expiresAt, 0)
	return &res, nil
}

// Finish moves a pending request owned by userID to a final status, and stores the response envelope of a completed request
// Only a pending request changes, so a request is finished once: if it's finished already, it returns false with the status it has
// It returns ErrRequestPayloadNotFound if there's no row for the request and its owner
func (s *RequestPayloadStore) Finish(ctx context.Context, state string, userID string, status V2RequestStatus, encryptedResult string) (current V2RequestStatus, applied bool, err error) {
	if !status.IsTerminal() {
		return "", false, fmt.Errorf("status '%s' is not final", status)
	}
	if status != V2RequestStatusCompleted {
		encryptedResult = ""
	}

	affected, err := s.db.Exec(ctx,
		`UPDATE v2_request_payloads SET status = $1, encrypted_result = $2
			WHERE state = $3 AND user_id = $4 AND status = $5`,
		string(status), encryptedResult, state, userID, string(V2RequestStatusPending),
	)
	if err != nil {
		return "", false, fmt.Errorf("error finishing request: %w", err)
	}
	if affected > 0 {
		return status, true, nil
	}

	err = s.db.
		QueryRow(ctx, `SELECT status FROM v2_request_payloads WHERE state = $1 AND user_id = $2`, state, userID).
		Scan(&current)
	if s.db.IsNoRowsError(err) {
		return "", false, ErrRequestPayloadNotFound
	} else if err != nil {
		return "", false, fmt.Errorf("error reading request status: %w", err)
	}

	return current, false, nil
}

// Delete removes the envelopes of the given requests owned by userID
// Requests with no row are ignored
func (s *RequestPayloadStore) Delete(ctx context.Context, userID string, states ...string) error {
	if len(states) == 0 {
		return nil
	}

	args := make([]any, 0, len(states)+1)
	args = append(args, userID)
	placeholders := make([]string, len(states))
	for i, state := range states {
		args = append(args, state)
		placeholders[i] = "$" + strconv.Itoa(i+2)
	}

	_, err := s.db.Exec(ctx,
		`DELETE FROM v2_request_payloads WHERE user_id = $1 AND state IN (`+strings.Join(placeholders, ", ")+`)`,
		args...,
	)
	if err != nil {
		return fmt.Errorf("error deleting request payloads: %w", err)
	}

	return nil
}

// ExpireOverdue moves the pending requests whose deadline is before the given time to the expired status, and returns them
// The revaulter.user actors expire their requests on time, so this only catches requests they missed, for example after their state was lost
// It must be called in a transaction that also records the expiry of each request in the audit log
func (s *RequestPayloadStore) ExpireOverdue(ctx context.Context, before time.Time) ([]RequestPayload, error) {
	rows, err := s.db.Query(ctx,
		`UPDATE v2_request_payloads SET status = $1
			WHERE status = $2 AND expires_at < $3
			RETURNING state, user_id, expires_at`,
		string(V2RequestStatusExpired), string(V2RequestStatusPending), before.Unix(),
	)
	if err != nil {
		return nil, fmt.Errorf("error expiring overdue requests: %w", err)
	}
	defer rows.Close()

	var res []RequestPayload
	for rows.Next() {
		var (
			p         RequestPayload
			expiresAt int64
		)
		err = rows.Scan(&p.State, &p.UserID, &expiresAt)
		if err != nil {
			return nil, fmt.Errorf("error reading expired request: %w", err)
		}
		p.ExpiresAt = time.Unix(expiresAt, 0)
		p.Status = V2RequestStatusExpired
		res = append(res, p)
	}

	err = rows.Err()
	if err != nil {
		return nil, fmt.Errorf("error reading expired requests: %w", err)
	}

	return res, nil
}

// DeleteExpired removes the envelopes of finished requests whose deadline is before the given time
// The revaulter.user actor deletes rows as it removes requests, so this only catches rows it missed, for example after its state was lost
// Pending rows are kept, so their expiry is recorded by ExpireOverdue first
func (s *RequestPayloadStore) DeleteExpired(ctx context.Context, before time.Time) (int64, error) {
	affected, err := s.db.Exec(ctx,
		`DELETE FROM v2_request_payloads WHERE expires_at < $1 AND status != $2`,
		before.Unix(), string(V2RequestStatusPending),
	)
	if err != nil {
		return 0, fmt.Errorf("error deleting expired request payloads: %w", err)
	}

	return affected, nil
}
