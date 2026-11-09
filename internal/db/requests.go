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

// ErrRequestPayloadNotFound is returned when no payload row matches the request and its owner
var ErrRequestPayloadNotFound = errors.New("request payload not found")

// RequestPayload contains the encrypted envelopes of a request
// The request's metadata lives in the revaulter.user actor, which is the only writer of these rows
type RequestPayload struct {
	State     string
	UserID    string
	ExpiresAt time.Time

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

// Insert stores the request envelope of a new request
func (s *RequestPayloadStore) Insert(ctx context.Context, in RequestPayload) error {
	_, err := s.db.Exec(ctx,
		`INSERT INTO v2_request_payloads (state, user_id, expires_at, encrypted_request, encrypted_result)
			VALUES ($1, $2, $3, $4, $5)`,
		in.State, in.UserID, in.ExpiresAt.Unix(), in.EncryptedRequest, in.EncryptedResult,
	)
	if err != nil {
		return fmt.Errorf("error inserting request payload: %w", err)
	}

	return nil
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
			`SELECT state, user_id, expires_at, encrypted_request, encrypted_result
				FROM v2_request_payloads
				WHERE state = $1 AND user_id = $2`,
			state, userID,
		).
		Scan(&res.State, &res.UserID, &expiresAt, &res.EncryptedRequest, &res.EncryptedResult)
	if s.db.IsNoRowsError(err) {
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("error reading request payload: %w", err)
	}

	res.ExpiresAt = time.Unix(expiresAt, 0)
	return &res, nil
}

// SetResult stores the response envelope of a request owned by userID
// It returns ErrRequestPayloadNotFound if there's no row for the request and its owner
func (s *RequestPayloadStore) SetResult(ctx context.Context, state string, userID string, encryptedResult string) error {
	affected, err := s.db.Exec(ctx,
		`UPDATE v2_request_payloads SET encrypted_result = $1 WHERE state = $2 AND user_id = $3`,
		encryptedResult, state, userID,
	)
	if err != nil {
		return fmt.Errorf("error storing request result: %w", err)
	}
	if affected == 0 {
		return ErrRequestPayloadNotFound
	}

	return nil
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

// DeleteExpired removes the envelopes of requests that expired before the given time
// The revaulter.user actor deletes rows as it removes requests, so this only catches rows it missed, for example after its state was lost
func (s *RequestPayloadStore) DeleteExpired(ctx context.Context, before time.Time) (int64, error) {
	affected, err := s.db.Exec(ctx,
		`DELETE FROM v2_request_payloads WHERE expires_at < $1`,
		before.Unix(),
	)
	if err != nil {
		return 0, fmt.Errorf("error deleting expired request payloads: %w", err)
	}

	return affected, nil
}
