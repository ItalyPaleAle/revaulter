package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
	"uuid"

	"github.com/italypaleale/go-sql-utils/adapter"
)

// EventType is a stable, dot-separated identifier for an audit event
// Format: <area>.<verb> (e.g. "auth.login_finish", "request.confirm")
// Constants below are the only values accepted by AuditStore.Insert
type EventType string

// Audit event types
// Adding a new constant requires updating EventType.Valid, AllEventTypes, and docs/07-audit-events.md
const (
	AuditAuthRegisterFinish     EventType = "auth.register_finish"
	AuditAuthFinalizeSignup     EventType = "auth.finalize_signup"
	AuditAuthLoginFinish        EventType = "auth.login_finish"
	AuditAuthLogout             EventType = "auth.logout"
	AuditAuthRequestKeyRegen    EventType = "auth.request_key_regenerate"
	AuditAuthRequestAuthMethods EventType = "auth.request_auth_methods_change"
	AuditAuthOIDCIssuerAdd      EventType = "auth.request_oidc_issuer_add"
	AuditAuthOIDCIssuerDelete   EventType = "auth.request_oidc_issuer_delete"
	AuditAuthAllowedIPsChange   EventType = "auth.allowed_ips_change"
	AuditAuthDisplayNameChange  EventType = "auth.display_name_change"
	AuditAuthWrappedKeyUpdate   EventType = "auth.wrapped_key_update"
	AuditAuthCredentialAdd      EventType = "auth.credential_add_finish" //nolint:gosec // event_type constant, not a credential value
	AuditAuthCredentialRename   EventType = "auth.credential_rename"     //nolint:gosec // event_type constant, not a credential value
	AuditAuthCredentialDelete   EventType = "auth.credential_delete"     //nolint:gosec // event_type constant, not a credential value
	AuditRequestCreate          EventType = "request.create"
	AuditRequestConfirm         EventType = "request.confirm"
	AuditRequestCancel          EventType = "request.cancel"
	AuditRequestExpire          EventType = "request.expire"
	AuditSigningKeyCreate       EventType = "signing_key.create"
	AuditSigningKeyPublish      EventType = "signing_key.publish"
	AuditSigningKeyUnpublish    EventType = "signing_key.unpublish"
	AuditSigningKeyDelete       EventType = "signing_key.delete"
	AuditSigningKeyAutoStore    EventType = "signing_key.auto_store"
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
	AuditAuthMethodSession     AuditAuthMethod = "session"
	AuditAuthMethodRequestKey  AuditAuthMethod = "request_key"
	AuditAuthMethodRequestOIDC AuditAuthMethod = "request_oidc"
	AuditAuthMethodSystem      AuditAuthMethod = "system"
	AuditAuthMethodNone        AuditAuthMethod = "none"
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
		AuditAuthRequestAuthMethods,
		AuditAuthOIDCIssuerAdd,
		AuditAuthOIDCIssuerDelete,
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

// AllEventTypes returns every declared event type, as strings
// The audit log stream validates its event-type filter against this, so a typo in the configuration fails at boot rather than silently emptying the feed
func AllEventTypes() []string {
	return []string{
		string(AuditAuthRegisterFinish),
		string(AuditAuthFinalizeSignup),
		string(AuditAuthLoginFinish),
		string(AuditAuthLogout),
		string(AuditAuthRequestKeyRegen),
		string(AuditAuthRequestAuthMethods),
		string(AuditAuthOIDCIssuerAdd),
		string(AuditAuthOIDCIssuerDelete),
		string(AuditAuthAllowedIPsChange),
		string(AuditAuthDisplayNameChange),
		string(AuditAuthWrappedKeyUpdate),
		string(AuditAuthCredentialAdd),
		string(AuditAuthCredentialRename),
		string(AuditAuthCredentialDelete),
		string(AuditRequestCreate),
		string(AuditRequestConfirm),
		string(AuditRequestCancel),
		string(AuditRequestExpire),
		string(AuditSigningKeyCreate),
		string(AuditSigningKeyPublish),
		string(AuditSigningKeyUnpublish),
		string(AuditSigningKeyDelete),
		string(AuditSigningKeyAutoStore),
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
	case AuditAuthMethodSession, AuditAuthMethodRequestKey, AuditAuthMethodRequestOIDC, AuditAuthMethodSystem, AuditAuthMethodNone:
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
	// UserID filters to events where actor_user_id matches
	// Empty means no actor filter
	UserID string
	// System filters to events written by a background/system path (auth_method = "system")
	System bool
	// EventType filters to a single event type
	// Empty means no event-type filter
	EventType EventType
	// SinceUnix and UntilUnix bound the created_at range
	// Zero means no bound on that side
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

const (
	// auditInsertColumns is the list of columns written by an INSERT into v2_audit_events
	auditInsertColumns = `id, created_at, event_type, outcome, auth_method, actor_user_id, target_user_id, signing_key_id, credential_id, request_state, http_request_id, client_ip, user_agent, metadata`
	// auditInsertColumnCount is the number of columns in auditInsertColumns
	auditInsertColumnCount = 14
	// auditInsertBatchSize caps the rows written by a single INSERT statement
	auditInsertBatchSize = 64
)

// Insert validates and writes an audit event row
func (s *AuditStore) Insert(ctx context.Context, data AuditEventInput) (AuditEvent, error) {
	ev, err := prepareAuditEvent(data, time.Now())
	if err != nil {
		return AuditEvent{}, err
	}

	err = s.insertRows(ctx, ev)
	if err != nil {
		return AuditEvent{}, err
	}

	return ev, nil
}

// InsertMany validates and writes multiple audit event rows, using one INSERT statement for up to auditInsertBatchSize rows
// If any event fails validation, nothing is written
// When there are more rows than auditInsertBatchSize, callers must ensure to invoke this in a transaction to write all rows atomically
func (s *AuditStore) InsertMany(ctx context.Context, data []AuditEventInput) (err error) {
	if len(data) == 0 {
		return nil
	}

	now := time.Now()
	events := make([]AuditEvent, len(data))
	for i := range data {
		events[i], err = prepareAuditEvent(data[i], now)
		if err != nil {
			return err
		}
	}

	for batch := range slices.Chunk(events, auditInsertBatchSize) {
		err = s.insertRows(ctx, batch...)
		if err != nil {
			return err
		}
	}

	return nil
}

// prepareAuditEvent validates the input and returns the audit event to write, with a new ID
func prepareAuditEvent(data AuditEventInput, now time.Time) (AuditEvent, error) {
	err := data.Validate()
	if err != nil {
		return AuditEvent{}, err
	}

	metadata := data.Metadata
	if len(metadata) == 0 {
		metadata = json.RawMessage("{}")
	}

	return AuditEvent{
		// Use UUIDv7 so rows are time-sortable
		ID:            uuid.NewV7().String(),
		CreatedAt:     time.Unix(now.Unix(), 0),
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

// insertRows writes the given audit events with a single INSERT statement
func (s *AuditStore) insertRows(ctx context.Context, events ...AuditEvent) error {
	var query strings.Builder
	query.WriteString(`INSERT INTO v2_audit_events (` + auditInsertColumns + `) VALUES `)

	args := make([]any, 0, len(events)*auditInsertColumnCount)
	for i, ev := range events {
		if i > 0 {
			query.WriteString(", ")
		}

		query.WriteString("(")
		for c := 1; c <= auditInsertColumnCount; c++ {
			if c > 1 {
				query.WriteString(", ")
			}
			query.WriteString("$")
			query.WriteString(strconv.Itoa(len(args) + c))

			// We cast both placeholders explicitly so pgx can pass the Go string straight through without driver-side type juggling
			if s.kind == BackendPostgres {
				switch c {
				case 1:
					query.WriteString("::uuid")
				case auditInsertColumnCount:
					query.WriteString("::jsonb")
				}
			}
		}
		query.WriteString(")")

		args = append(args,
			ev.ID, ev.CreatedAt.Unix(), string(ev.EventType), string(ev.Outcome), string(ev.AuthMethod),
			nullableString(ev.ActorUserID), nullableString(ev.TargetUserID), nullableString(ev.SigningKeyID), nullableString(ev.CredentialID),
			nullableString(ev.RequestState), nullableString(ev.HTTPRequestID), nullableString(ev.ClientIP), nullableString(ev.UserAgent),
			string(ev.Metadata),
		)
	}

	_, err := s.db.Exec(ctx, query.String(), args...)
	return err
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

	// Fetch 1 extra row to see if there are more records
	// The extra one will be discarded
	args = append(args, limit+1)

	// With an empty filter (no clauses) we want a bare SELECT, otherwise stitch the AND-joined WHERE clause in
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
	// The version is stored in the high nibble of byte 6, per RFC 9562 § 4.2
	if u[6]>>4 != 7 {
		return "", ErrAuditInvalidCursor
	}

	return cursor, nil
}

// RequestAuditMetadata builds the metadata payload shared by all request.* audit events
// The note is omitted when empty so the metadata payload stays compact
func RequestAuditMetadata(operation, algorithm, keyLabel, note string) json.RawMessage {
	payload := map[string]any{
		"operation": operation,
		"algorithm": algorithm,
		"keyLabel":  keyLabel,
	}
	if note != "" {
		payload["note"] = note
	}

	b, err := json.Marshal(payload)
	if err != nil {
		return nil
	}
	return b
}
