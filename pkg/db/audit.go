package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/italypaleale/go-sql-utils/adapter"
)

// EventType is a stable, dot-separated identifier for an audit event
// Format: <area>.<verb> (e.g. "auth.login_finish", "request.confirm")
// Constants below are the only values accepted by AuditStore.Insert
type EventType string

// Audit event types
// Adding a new constant requires updating docs/07-audit-events.md
const (
	AuditAuthRegisterFinish    EventType = "auth.register_finish"
	AuditAuthFinalizeSignup    EventType = "auth.finalize_signup"
	AuditAuthLoginFinish       EventType = "auth.login_finish"
	AuditAuthLogout            EventType = "auth.logout"
	AuditAuthRequestKeyRegen   EventType = "auth.request_key_regenerate"
	AuditAuthAllowedIPsChange  EventType = "auth.allowed_ips_change"
	AuditAuthDisplayNameChange EventType = "auth.display_name_change"
	AuditAuthWrappedKeyUpdate  EventType = "auth.wrapped_key_update"
	AuditAuthCredentialAdd     EventType = "auth.credential_add_finish" //nolint:gosec // event_type constant, not a credential value
	AuditAuthCredentialRename  EventType = "auth.credential_rename"     //nolint:gosec // event_type constant, not a credential value
	AuditAuthCredentialDelete  EventType = "auth.credential_delete"     //nolint:gosec // event_type constant, not a credential value
	AuditRequestCreate         EventType = "request.create"
	AuditRequestConfirm        EventType = "request.confirm"
	AuditRequestCancel         EventType = "request.cancel"
	AuditRequestExpire         EventType = "request.expire"
	AuditSigningKeyCreate      EventType = "signing_key.create"
	AuditSigningKeyPublish     EventType = "signing_key.publish"
	AuditSigningKeyUnpublish   EventType = "signing_key.unpublish"
	AuditSigningKeyDelete      EventType = "signing_key.delete"
	AuditSigningKeyAutoStore   EventType = "signing_key.auto_store"
)

// AuditOutcome is the result of an audited action
type AuditOutcome string

const (
	AuditOutcomeSuccess AuditOutcome = "success"
	AuditOutcomeFailure AuditOutcome = "failure"
	AuditOutcomeDenied  AuditOutcome = "denied"
)

// AuditAuthMethod identifies how the actor authenticated
type AuditAuthMethod string

const (
	AuditAuthMethodSession    AuditAuthMethod = "session"
	AuditAuthMethodRequestKey AuditAuthMethod = "request_key"
	AuditAuthMethodSystem     AuditAuthMethod = "system"
	AuditAuthMethodNone       AuditAuthMethod = "none"
)

// Caps applied at insert time
const (
	auditMaxMetadataBytes  = 4 << 10
	auditMaxUserAgentChars = 512
	auditMaxIPChars        = 64
)

// Valid reports whether the receiver matches one of the declared event_type constants
func (e EventType) Valid() bool {
	switch e {
	case AuditAuthRegisterFinish,
		AuditAuthFinalizeSignup,
		AuditAuthLoginFinish,
		AuditAuthLogout,
		AuditAuthRequestKeyRegen,
		AuditAuthAllowedIPsChange,
		AuditAuthDisplayNameChange,
		AuditAuthWrappedKeyUpdate,
		AuditAuthCredentialAdd,
		AuditAuthCredentialRename,
		AuditAuthCredentialDelete,
		AuditRequestCreate,
		AuditRequestConfirm,
		AuditRequestCancel,
		AuditRequestExpire,
		AuditSigningKeyCreate,
		AuditSigningKeyPublish,
		AuditSigningKeyUnpublish,
		AuditSigningKeyDelete,
		AuditSigningKeyAutoStore:
		return true
	default:
		return false
	}
}

// Valid reports whether the receiver matches one of the declared outcome constants
func (o AuditOutcome) Valid() bool {
	switch o {
	case AuditOutcomeSuccess, AuditOutcomeFailure, AuditOutcomeDenied:
		return true
	default:
		return false
	}
}

// Valid reports whether the receiver matches one of the declared auth_method constants
func (m AuditAuthMethod) Valid() bool {
	switch m {
	case AuditAuthMethodSession, AuditAuthMethodRequestKey, AuditAuthMethodSystem, AuditAuthMethodNone:
		return true
	default:
		return false
	}
}

// AuditEvent is a stored audit-log row
type AuditEvent struct {
	ID            string
	CreatedAt     time.Time
	EventType     EventType
	Outcome       AuditOutcome
	AuthMethod    AuditAuthMethod
	ActorUserID   *string
	TargetUserID  *string
	SigningKeyID  *string
	CredentialID  *string
	RequestState  *string
	HTTPRequestID *string
	ClientIP      *string
	UserAgent     *string
	Metadata      json.RawMessage
}

// AuditEventInput is the payload for AuditStore.Insert
// Optional pointer fields are stored as SQL NULL when nil
// Metadata, if empty, is stored as the literal "{}" JSON object
type AuditEventInput struct {
	EventType     EventType
	Outcome       AuditOutcome
	AuthMethod    AuditAuthMethod
	ActorUserID   *string
	TargetUserID  *string
	SigningKeyID  *string
	CredentialID  *string
	RequestState  *string
	HTTPRequestID *string
	ClientIP      *string
	UserAgent     *string
	Metadata      json.RawMessage
}

// AuditFilter narrows List results
// Empty fields are treated as "no filter"
// UserID and System are mutually exclusive: a system event has no actor user, so combining them is rejected with ErrAuditFilterConflict
type AuditFilter struct {
	// UserID filters to events where actor_user_id matches; empty means no actor filter
	UserID string
	// System filters to events written by a background/system path (auth_method = "system")
	System bool
	// EventType filters to a single event type; empty means no event-type filter
	EventType EventType
	// SinceUnix and UntilUnix bound the created_at range; zero means no bound on that side
	SinceUnix int64
	UntilUnix int64
}

// Errors returned by AuditStore
var (
	ErrAuditInvalidEventType  = errors.New("invalid audit event_type")
	ErrAuditInvalidOutcome    = errors.New("invalid audit outcome")
	ErrAuditInvalidAuthMethod = errors.New("invalid audit auth_method")
	ErrAuditMetadataTooLarge  = fmt.Errorf("audit metadata exceeds %d bytes", auditMaxMetadataBytes)
	ErrAuditMetadataInvalid   = errors.New("audit metadata is not valid JSON")
	ErrAuditUserAgentTooLong  = fmt.Errorf("audit user_agent exceeds %d chars", auditMaxUserAgentChars)
	ErrAuditClientIPTooLong   = fmt.Errorf("audit client_ip exceeds %d chars", auditMaxIPChars)
	ErrAuditInvalidCursor     = errors.New("invalid audit list cursor")
	ErrAuditFilterConflict    = errors.New("audit filter UserID and System are mutually exclusive")
)

type AuditStore struct {
	db   adapter.Querier
	kind BackendKind
}

func NewAuditStore(db adapter.Querier, kind BackendKind) (*AuditStore, error) {
	if db == nil {
		return nil, errors.New("db is nil")
	}

	return &AuditStore{
		db:   db,
		kind: kind,
	}, nil
}

// AuditStore returns an instance of AuditStore
func (db *DB) AuditStore() *AuditStore {
	as, err := NewAuditStore(db, db.kind)
	if err != nil {
		// Indicates a development-time error
		panic(err)
	}

	return as
}

// AuditStore returns an instance of AuditStore for the transaction
func (tx *DbTx) AuditStore() *AuditStore {
	as, err := NewAuditStore(tx, tx.kind)
	if err != nil {
		// Indicates a development-time error
		panic(err)
	}

	return as
}

// Insert validates and writes an audit event row
func (s *AuditStore) Insert(ctx context.Context, data AuditEventInput) (AuditEvent, error) {
	err := data.Validate()
	if err != nil {
		return AuditEvent{}, err
	}

	// Use UUIDv7 so rows are time-sortable
	id, err := uuid.NewV7()
	if err != nil {
		return AuditEvent{}, fmt.Errorf("failed to generate audit id: %w", err)
	}

	metadata := data.Metadata
	if len(metadata) == 0 {
		metadata = json.RawMessage("{}")
	}

	now := time.Now().Unix()

	// Postgres types are stricter than SQLite: id is uuid and metadata is jsonb
	// We cast both placeholders explicitly so pgx can pass the Go string straight through without driver-side type juggling
	idPlaceholder := "$1"
	metadataPlaceholder := "$14"
	if s.kind == BackendPostgres {
		idPlaceholder = "$1::uuid"
		metadataPlaceholder = "$14::jsonb"
	}

	_, err = s.db.Exec(ctx,
		`INSERT INTO v2_audit_events
			(id, created_at, event_type, outcome, auth_method, actor_user_id, target_user_id, signing_key_id, credential_id, request_state, http_request_id, client_ip, user_agent, metadata)
			VALUES (`+idPlaceholder+`, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, `+metadataPlaceholder+`)`,
		id.String(), now, string(data.EventType), string(data.Outcome), string(data.AuthMethod),
		nullableString(data.ActorUserID), nullableString(data.TargetUserID), nullableString(data.SigningKeyID), nullableString(data.CredentialID),
		nullableString(data.RequestState), nullableString(data.HTTPRequestID), nullableString(data.ClientIP), nullableString(data.UserAgent),
		string(metadata),
	)
	if err != nil {
		return AuditEvent{}, err
	}

	return AuditEvent{
		ID:            id.String(),
		CreatedAt:     time.Unix(now, 0),
		EventType:     data.EventType,
		Outcome:       data.Outcome,
		AuthMethod:    data.AuthMethod,
		ActorUserID:   clonePtr(data.ActorUserID),
		TargetUserID:  clonePtr(data.TargetUserID),
		SigningKeyID:  clonePtr(data.SigningKeyID),
		CredentialID:  clonePtr(data.CredentialID),
		RequestState:  clonePtr(data.RequestState),
		HTTPRequestID: clonePtr(data.HTTPRequestID),
		ClientIP:      clonePtr(data.ClientIP),
		UserAgent:     clonePtr(data.UserAgent),
		Metadata:      append(json.RawMessage(nil), metadata...),
	}, nil
}

// List returns audit events matching the given filter
// With an empty filter every row is returned (newest first)
// Results are ordered by id DESC: id is a UUIDv7 so this is the same as time-descending with ms-resolution tie-breaks built in
// nextCursor is empty when there are no more results
func (s *AuditStore) List(ctx context.Context, filter AuditFilter, limit int, cursor string) ([]AuditEvent, string, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 500 {
		limit = 500
	}

	if filter.UserID != "" && filter.System {
		return nil, "", ErrAuditFilterConflict
	}

	if filter.EventType != "" && !filter.EventType.Valid() {
		return nil, "", ErrAuditInvalidEventType
	}

	cursorID, err := validateAuditCursor(cursor)
	if err != nil {
		return nil, "", err
	}

	// Build args and clauses
	args := make([]any, 0, 5)
	clauses := make([]string, 0, 5)

	if filter.UserID != "" {
		args = append(args, filter.UserID)
		clauses = append(clauses, fmt.Sprintf("actor_user_id = $%d", len(args)))
	}
	if filter.System {
		args = append(args, string(AuditAuthMethodSystem))
		clauses = append(clauses, fmt.Sprintf("auth_method = $%d", len(args)))
	}

	if filter.EventType != "" {
		args = append(args, string(filter.EventType))
		clauses = append(clauses, fmt.Sprintf("event_type = $%d", len(args)))
	}
	if filter.SinceUnix > 0 {
		args = append(args, filter.SinceUnix)
		clauses = append(clauses, fmt.Sprintf("created_at >= $%d", len(args)))
	}
	if filter.UntilUnix > 0 {
		args = append(args, filter.UntilUnix)
		clauses = append(clauses, fmt.Sprintf("created_at <= $%d", len(args)))
	}
	if cursor != "" {
		args = append(args, cursorID)
		// Postgres id column is uuid: cast the string parameter so the comparison runs against the typed column
		idCast := ""
		if s.kind == BackendPostgres {
			idCast = "::uuid"
		}
		clauses = append(clauses, fmt.Sprintf("id < $%d%s", len(args), idCast))
	}

	// Fetch 1 extra row to see if there are more records; the extra one will be discarded
	args = append(args, limit+1)

	// With an empty filter (no clauses) we want a bare SELECT; otherwise stitch the AND-joined WHERE clause in
	whereClause := ""
	if len(clauses) > 0 {
		whereClause = "\n\t\tWHERE " + strings.Join(clauses, " AND ")
	}

	query := `SELECT id, created_at, event_type, outcome, auth_method, actor_user_id, target_user_id, signing_key_id, credential_id, request_state, http_request_id, client_ip, user_agent, metadata
		FROM v2_audit_events` + whereClause + `
		ORDER BY id DESC
		LIMIT $` + strconv.Itoa(len(args))

	rows, err := s.db.Query(ctx, query, args...)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()

	out := make([]AuditEvent, 0, limit)
	for rows.Next() {
		var (
			rec       AuditEvent
			createdAt int64
			actor     sql.NullString
			target    sql.NullString
			signing   sql.NullString
			cred      sql.NullString
			reqState  sql.NullString
			httpReq   sql.NullString
			ip        sql.NullString
			ua        sql.NullString
			eventType string
			outcome   string
			method    string
			metadata  []byte
		)
		err = rows.Scan(&rec.ID, &createdAt, &eventType, &outcome, &method, &actor, &target, &signing, &cred, &reqState, &httpReq, &ip, &ua, &metadata)
		if err != nil {
			return nil, "", err
		}

		rec.CreatedAt = time.Unix(createdAt, 0)
		rec.EventType = EventType(eventType)
		rec.Outcome = AuditOutcome(outcome)
		rec.AuthMethod = AuditAuthMethod(method)
		rec.ActorUserID = nullStringToPtr(actor)
		rec.TargetUserID = nullStringToPtr(target)
		rec.SigningKeyID = nullStringToPtr(signing)
		rec.CredentialID = nullStringToPtr(cred)
		rec.RequestState = nullStringToPtr(reqState)
		rec.HTTPRequestID = nullStringToPtr(httpReq)
		rec.ClientIP = nullStringToPtr(ip)
		rec.UserAgent = nullStringToPtr(ua)
		if len(metadata) > 0 {
			rec.Metadata = append(json.RawMessage(nil), metadata...)
		} else {
			rec.Metadata = json.RawMessage("{}")
		}

		out = append(out, rec)
	}

	err = rows.Err()
	if err != nil {
		return nil, "", err
	}

	var nextCursor string
	if len(out) > limit {
		last := out[limit-1]
		out = out[:limit]
		nextCursor = last.ID
	}

	return out, nextCursor, nil
}

// PruneBefore removes rows created before a threshold
// Returns the number of rows removed
func (s *AuditStore) PruneBefore(ctx context.Context, beforeUnix int64) (int64, error) {
	affected, err := s.db.Exec(ctx, `DELETE FROM v2_audit_events WHERE created_at < $1`, beforeUnix)
	if err != nil {
		return 0, err
	}

	return affected, nil
}

// Validate checks the input for validity
func (in *AuditEventInput) Validate() error {
	if !in.EventType.Valid() {
		return ErrAuditInvalidEventType
	}
	if !in.Outcome.Valid() {
		return ErrAuditInvalidOutcome
	}
	if !in.AuthMethod.Valid() {
		return ErrAuditInvalidAuthMethod
	}

	if len(in.Metadata) > auditMaxMetadataBytes {
		return ErrAuditMetadataTooLarge
	}
	if len(in.Metadata) > 0 && !json.Valid(in.Metadata) {
		return ErrAuditMetadataInvalid
	}

	if in.UserAgent != nil && len(*in.UserAgent) > auditMaxUserAgentChars {
		// User-agent strings over the cap are silently trimmed in place
		trimmed := (*in.UserAgent)[:auditMaxUserAgentChars]
		in.UserAgent = &trimmed
	}

	if in.ClientIP != nil && len(*in.ClientIP) > auditMaxIPChars {
		return ErrAuditClientIPTooLong
	}

	return nil
}

// validateAuditCursor returns the cursor verbatim after checking it parses as a UUID
func validateAuditCursor(cursor string) (string, error) {
	if cursor == "" {
		return "", nil
	}

	// Validate that the cursor is a UUID v7
	u, err := uuid.Parse(cursor)
	if err != nil {
		return "", ErrAuditInvalidCursor
	}
	if u.Version() != 7 {
		return "", ErrAuditInvalidCursor
	}

	return cursor, nil
}
