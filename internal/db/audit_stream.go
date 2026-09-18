package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strconv"
	"time"
	"uuid"

	"github.com/italypaleale/go-kit/auditlogs/siem"
	"github.com/italypaleale/go-sql-utils/adapter"
)

// AuditStreamCursorKey is the v2_kv key the audit stream cursor is stored under
const AuditStreamCursorKey = "audit_log_cursor"

// AuditStreamStore implements siem.Store on top of v2_audit_events and v2_kv
//
// Reading committed rows back out of the table, rather than pushing from the handler, is what makes the feed survive a crash and keeps it from ever shipping an event whose transaction rolled back
// Both backends have their own shipping key, assigned by the database itself:
//   - Postgres orders by (xact_id, id) and only considers rows whose transaction has settled
//   - SQLite orders by seq, an AUTOINCREMENT column assigned under the write lock that `_txlock=immediate` takes at BEGIN, so insert order is commit order
type AuditStreamStore struct {
	db   adapter.Querier
	kv   *KVStore
	kind BackendKind
	etag string
}

func NewAuditStreamStore(db adapter.Querier, kind BackendKind) (*AuditStreamStore, error) {
	if db == nil {
		return nil, errors.New("db is nil")
	}

	kv, err := NewKVStore(db)
	if err != nil {
		return nil, err
	}

	return &AuditStreamStore{
		db:   db,
		kv:   kv,
		kind: kind,
	}, nil
}

// AuditStreamStore returns an instance of AuditStreamStore
func (db *DB) AuditStreamStore() *AuditStreamStore {
	s, err := NewAuditStreamStore(db, db.kind)
	if err != nil {
		// Indicates a development-time error
		panic(err)
	}

	return s
}

// GetPosition returns the stored cursor
// Returns siem.ErrPositionNotFound when the cursor has never been written (indicating not yet bootstrapped)
func (s *AuditStreamStore) GetPosition(ctx context.Context) (siem.Position, error) {
	val, etag, err := s.kv.Get(ctx, AuditStreamCursorKey)
	if errors.Is(err, ErrKVNotFound) {
		return siem.Position{}, siem.ErrPositionNotFound
	} else if err != nil {
		return siem.Position{}, err
	}

	pos, err := siem.ParsePosition(val)
	if err != nil {
		return siem.Position{}, err
	}

	s.etag = etag

	return pos, nil
}

// SetPosition advances the cursor with a compare-and-swap against prev
func (s *AuditStreamStore) SetPosition(ctx context.Context, _ siem.Position, next siem.Position) (bool, error) {
	etag, ok, err := s.kv.CompareAndSwap(ctx, AuditStreamCursorKey, s.etag, next.Encode())
	if err != nil || !ok {
		return false, err
	}

	s.etag = etag

	return true, nil
}

// BootstrapToHead seeds the cursor at the current high-water mark, so only events created from this point on are ever shipped
func (s *AuditStreamStore) BootstrapToHead(ctx context.Context) (siem.Position, bool, error) {
	head, err := s.head(ctx)
	if err != nil {
		return siem.Position{}, false, err
	}

	etag, seeded, err := s.kv.SetIfAbsent(ctx, AuditStreamCursorKey, head.Encode())
	if err != nil {
		return siem.Position{}, false, err
	}
	if seeded {
		s.etag = etag
		return head, true, nil
	}

	// An earlier run already seeded the cursor: resume from whatever it holds
	existing, err := s.GetPosition(ctx)
	if err != nil {
		return siem.Position{}, false, err
	}

	return existing, false, nil
}

// head returns the position of the last settled event, or a zero position when the table holds none
func (s *AuditStreamStore) head(ctx context.Context) (pos siem.Position, err error) {
	pos = siem.Position{V: siem.PositionVersion}

	var createdAt int64
	if s.kind == BackendPostgres {
		err = s.db.
			QueryRow(ctx, `SELECT xact_id::text, id::text, created_at FROM v2_audit_events
				WHERE xact_id < pg_snapshot_xmin(pg_current_snapshot())
				ORDER BY xact_id DESC, id DESC
				LIMIT 1`).
			Scan(&pos.XactID, &pos.EventID, &createdAt)
	} else {
		err = s.db.
			QueryRow(ctx, `SELECT seq, created_at FROM v2_audit_events ORDER BY seq DESC LIMIT 1`).
			Scan(&pos.Seq, &createdAt)
	}
	if s.db.IsNoRowsError(err) {
		// An empty audit table seeds a legitimately all-zero cursor
		// That is unambiguous here only because bootstrap is keyed on key presence, not on the cursor's value
		return pos, nil
	} else if err != nil {
		return siem.Position{}, err
	}

	pos.EventCreatedAt = createdAt

	return pos, nil
}

// ListForShipping returns up to limit settled events that sort after pos, in shipping-key order
func (s *AuditStreamStore) ListForShipping(ctx context.Context, pos siem.Position, limit int) ([]siem.Event, error) {
	if limit <= 0 {
		limit = 1
	}

	query, args := s.shippingQuery(`SELECT `+s.shippingKeyColumns()+`, id, created_at, event_type, outcome, auth_method, actor_user_id, target_user_id, signing_key_id, credential_id, request_state, http_request_id, client_ip, user_agent, metadata FROM v2_audit_events`, pos)
	query += s.shippingOrder() + " LIMIT $" + strconv.Itoa(len(args)+1)
	args = append(args, limit)

	rows, err := s.db.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]siem.Event, 0, limit)
	for rows.Next() {
		ev, err := s.scanEvent(rows.Scan)
		if err != nil {
			return nil, err
		}

		out = append(out, ev)
	}

	err = rows.Err()
	if err != nil {
		return nil, err
	}

	return out, nil
}

// CountPending returns how many settled events sort after pos
func (s *AuditStreamStore) CountPending(ctx context.Context, pos siem.Position) (int64, error) {
	query, args := s.shippingQuery(`SELECT COUNT(*) FROM v2_audit_events`, pos)

	var count int64
	err := s.db.QueryRow(ctx, query, args...).Scan(&count)
	if err != nil {
		return 0, err
	}

	return count, nil
}

// shippingQuery appends the backend-specific settled-ness predicate and cursor comparison to a base statement
func (s *AuditStreamStore) shippingQuery(base string, pos siem.Position) (string, []any) {
	if s.kind == BackendPostgres {
		// pg_snapshot_xmin(pg_current_snapshot()) is the lowest still-running transaction id
		// Any row below it is settled: committed and visible, or aborted and gone forever
		// There is no in-flight transaction that could later reveal a row below that bound, so nothing can appear behind the cursor
		xactID := pos.XactID
		if xactID == "" {
			xactID = "0"
		}
		eventID := pos.EventID
		if eventID == "" {
			eventID = uuid.Nil().String()
		}

		return base + `
			WHERE xact_id < pg_snapshot_xmin(pg_current_snapshot())
			AND (xact_id, id) > ($1::xid8, $2::uuid)`, []any{xactID, eventID}
	}

	// In SQLite, BEGIN IMMEDIATE serializes writers, so seq is assigned under the write lock and insert order is commit order
	return base + `
		WHERE seq > $1`, []any{pos.Seq}
}

// shippingKeyColumns returns the backend's shipping key, selected ahead of the event columns
func (s *AuditStreamStore) shippingKeyColumns() string {
	if s.kind == BackendPostgres {
		return "xact_id::text"
	}

	return "seq"
}

// shippingOrder returns the ORDER BY clause matching the backend's shipping key
func (s *AuditStreamStore) shippingOrder() string {
	if s.kind == BackendPostgres {
		// This is not commit order, since transaction 101 can commit before transaction 100, so events may ship in a slightly different order than they committed
		// That is fine: the requirement is never to skip an event, and completeness holds exactly
		return `
			ORDER BY xact_id, id`
	}

	return `
		ORDER BY seq`
}

// scanEvent reads one row into a siem.Event, including its position
// It takes the row's Scan method rather than the row itself because the adapter does not export its rows interface
func (s *AuditStreamStore) scanEvent(scan func(dest ...any) error) (siem.Event, error) {
	var (
		ev        siem.Event
		seq       int64
		xactID    string
		createdAt int64
		actor     sql.NullString
		target    sql.NullString
		signing   sql.NullString
		cred      sql.NullString
		reqState  sql.NullString
		httpReq   sql.NullString
		ip        sql.NullString
		ua        sql.NullString
		metadata  []byte
	)

	dest := []any{&createdAt, &ev.EventType, &ev.Outcome, &ev.AuthMethod, &actor, &target, &signing, &cred, &reqState, &httpReq, &ip, &ua, &metadata}
	if s.kind == BackendPostgres {
		dest = append([]any{&xactID, &ev.ID}, dest...)
	} else {
		dest = append([]any{&seq, &ev.ID}, dest...)
	}

	err := scan(dest...)
	if err != nil {
		return siem.Event{}, err
	}

	ev.Time = time.Unix(createdAt, 0).UTC()
	ev.ActorUserID = actor.String
	ev.TargetUserID = target.String
	ev.HTTPRequestID = httpReq.String
	ev.ClientIP = ip.String
	ev.UserAgent = ua.String

	// Correlation ids that go-kit's generic event has no field for
	// They stay out of metadata so the handler's own payload reaches the collector byte for byte
	// Empty values are dropped while the event is encoded, so a NULL column is simply omitted
	ev.Attributes = map[string]string{
		"signingKeyId": signing.String,
		"credentialId": cred.String,
		"requestState": reqState.String,
	}

	if len(metadata) > 0 {
		ev.Metadata = append(json.RawMessage(nil), metadata...)
	}

	ev.Position = siem.Position{
		V:              siem.PositionVersion,
		Seq:            seq,
		XactID:         xactID,
		EventID:        ev.ID,
		EventCreatedAt: createdAt,
	}

	return ev, nil
}
