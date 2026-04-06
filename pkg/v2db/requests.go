package v2db

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	db         *DB
	payloadKey []byte
	log        *slog.Logger
}

func NewRequestStore(db *DB, payloadKey []byte, logger *slog.Logger) (*RequestStore, error) {
	if db == nil {
		return nil, errors.New("db is nil")
	}
	if len(payloadKey) != 32 {
		return nil, fmt.Errorf("invalid DB payload key length: got %d, want 32", len(payloadKey))
	}

	if logger == nil {
		logger = slog.Default()
	}
	s := &RequestStore{
		db:         db,
		payloadKey: payloadKey,
		log:        logger,
	}

	return s, nil
}

func (s *RequestStore) CreateRequest(ctx context.Context, in CreateRequestInput) error {
	payloadCiphertext, payloadNonce, err := s.sealJSON("request-payload", in.State, in.Body)
	if err != nil {
		return err
	}

	note := in.Body.Note
	now := in.CreatedAt.Unix()
	expires := in.ExpiresAt.Unix()
	_, err = s.db.db.Exec(ctx,
		`INSERT INTO v2_requests
			(state, status, operation, target_user, key_label, algorithm, requestor_ip, note, created_at, expires_at, updated_at, payload_ciphertext, payload_nonce)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
		in.State, string(V2RequestStatusPending), in.Operation, in.Body.TargetUser, in.Body.KeyLabel, in.Body.Algorithm, in.RequestorIP, note, now, expires, now, payloadCiphertext, payloadNonce,
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
		State, Status, Operation, TargetUser, KeyLabel, Algorithm, RequestorIP, Note string
		CreatedAt, ExpiresAt, UpdatedAt                                              int64
		PayloadCiphertext, PayloadNonce                                              []byte
		ResultCiphertext, ResultNonce                                                []byte
	}
	var row rowT

	err := s.db.db.
		QueryRow(ctx,
			`SELECT state ,status ,operation ,target_user ,key_label ,algorithm ,requestor_ip ,note ,created_at ,expires_at ,updated_at ,payload_ciphertext ,payload_nonce ,result_ciphertext ,result_nonce FROM v2_requests WHERE state = $1`,
			state,
		).
		Scan(
			&row.State, &row.Status, &row.Operation, &row.TargetUser, &row.KeyLabel, &row.Algorithm, &row.RequestorIP, &row.Note, &row.CreatedAt, &row.ExpiresAt, &row.UpdatedAt, &row.PayloadCiphertext, &row.PayloadNonce, &row.ResultCiphertext, &row.ResultNonce,
		)
	if s.db.db.IsNoRowsError(err) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}

	var body protocolv2.RequestCreateBody
	err = s.openJSON("request-payload", row.State, row.PayloadCiphertext, row.PayloadNonce, &body)
	if err != nil {
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
		err = s.openJSON("request-result", row.State, row.ResultCiphertext, row.ResultNonce, &env)
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
		`SELECT state,status,operation,target_user,key_label,algorithm,requestor_ip,note,created_at,expires_at FROM v2_requests WHERE status = $1 ORDER BY created_at ASC`,
		string(V2RequestStatusPending),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var item V2RequestListItem
		err = rows.Scan(&item.State, &item.Status, &item.Operation, &item.TargetUser, &item.KeyLabel, &item.Algorithm, &item.Requestor, &item.Note, &item.Date, &item.Expiry)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}

	return out, rows.Err()
}

func (s *RequestStore) CompleteRequest(ctx context.Context, state string, env protocolv2.ResponseEnvelope) (bool, error) {
	ct, nonce, err := s.sealJSON("request-result", state, env)
	if err != nil {
		return false, err
	}

	now := time.Now().Unix()
	affected, err := s.db.db.Exec(ctx,
		`UPDATE v2_requests SET status = $1, updated_at = $2, result_ciphertext = $3, result_nonce = $4 WHERE state = $5 AND status = $6 AND expires_at >= $7`,
		string(V2RequestStatusCompleted), now, ct, nonce, state, string(V2RequestStatusPending), now,
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

func (s *RequestStore) ExpirePendingAndReturnStates(ctx context.Context, now time.Time) ([]string, error) {
	n := now.Unix()
	rows, err := s.db.db.Query(ctx,
		`UPDATE v2_requests SET status = $1, updated_at = $2 WHERE status = $3 AND expires_at < $4 RETURNING state`,
		string(V2RequestStatusExpired), n, string(V2RequestStatusPending), n,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var states []string
	for rows.Next() {
		var st string
		err = rows.Scan(&st)
		if err != nil {
			return nil, err
		}
		states = append(states, st)
	}

	return states, rows.Err()
}

// deriveOperationAEAD derives a per-operation AES-256-GCM AEAD from the payload using HKDF-SHA256
// Each unique (kind, id) pair gets its own derived key, achieving key binding and eliminating the AES-GCM nonce-collision risk across operations that would exist if a single key were reused with random nonces
func (s *RequestStore) deriveOperationAEAD(kind string, id string) (cipher.AEAD, error) {
	// Derive a new key using HKDF
	info := "revaulter|" + kind + "|" + id
	opKey, err := hkdf.Key(sha256.New, s.payloadKey, nil, info, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to derive operation key: %w", err)
	}

	// Create the AES-GCM cipher
	block, err := aes.NewCipher(opKey)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func (s *RequestStore) sealJSON(kind string, id string, v any) (ciphertext []byte, nonce []byte, err error) {
	// Encode to JSON
	plain, err := json.Marshal(v)
	if err != nil {
		return nil, nil, err
	}

	// Derive a key for this specific operation
	aead, err := s.deriveOperationAEAD(kind, id)
	if err != nil {
		return nil, nil, err
	}

	// Generate a random nonce
	nonce = make([]byte, aead.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, nil, err
	}

	// Encrypt the message
	ciphertext = aead.Seal(nil, nonce, plain, nil)
	return ciphertext, nonce, nil
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

func (s *RequestStore) openJSON(kind string, id string, ciphertext []byte, nonce []byte, out any) error {
	// Derive a key for this specific operation
	aead, err := s.deriveOperationAEAD(kind, id)
	if err != nil {
		return err
	}

	// Decrypt the message
	plain, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return err
	}

	// Decode from JSON
	err = json.Unmarshal(plain, out)
	if err != nil {
		return err
	}

	return nil
}
