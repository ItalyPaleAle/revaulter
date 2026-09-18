-- Rebuild v2_audit_events with an explicit AUTOINCREMENT primary key used as the audit stream shipping key
--
-- The implicit rowid is not safe as a cursor: VACUUM may renumber it on a table whose primary key is not an INTEGER PRIMARY KEY, and it restarts from 1 once the table is fully emptied, which a quiet instance reaches after 30 days of retention pruning
-- An explicit AUTOINCREMENT column survives VACUUM and, through sqlite_sequence, is never reused
CREATE TABLE v2_audit_events_new (
	seq INTEGER PRIMARY KEY AUTOINCREMENT,
	id TEXT NOT NULL UNIQUE,
	created_at INTEGER NOT NULL,
	event_type TEXT NOT NULL,
	outcome TEXT NOT NULL,
	auth_method TEXT NOT NULL,
	actor_user_id TEXT,
	target_user_id TEXT,
	signing_key_id TEXT,
	credential_id TEXT,
	request_state TEXT,
	http_request_id TEXT,
	client_ip TEXT,
	user_agent TEXT,
	metadata TEXT NOT NULL DEFAULT '{}'
);

-- ORDER BY id so existing rows get seq in UUIDv7 (time) order
INSERT INTO v2_audit_events_new
	(id, created_at, event_type, outcome, auth_method, actor_user_id, target_user_id, signing_key_id, credential_id, request_state, http_request_id, client_ip, user_agent, metadata)
SELECT id, created_at, event_type, outcome, auth_method, actor_user_id, target_user_id, signing_key_id, credential_id, request_state, http_request_id, client_ip, user_agent, metadata
FROM v2_audit_events ORDER BY id;

DROP TABLE v2_audit_events;

ALTER TABLE v2_audit_events_new RENAME TO v2_audit_events;

CREATE INDEX IF NOT EXISTS idx_v2_audit_events_created_at ON v2_audit_events(created_at);

CREATE INDEX IF NOT EXISTS idx_v2_audit_events_actor_id ON v2_audit_events(actor_user_id, id DESC);

CREATE INDEX IF NOT EXISTS idx_v2_audit_events_type_id ON v2_audit_events(event_type, id DESC);

-- Generic key/value table for small pieces of application state, such as the audit stream cursor
CREATE TABLE IF NOT EXISTS v2_kv (
	key TEXT NOT NULL PRIMARY KEY,
	value TEXT NOT NULL,
	-- Regenerated on every write
	etag TEXT NOT NULL
);
