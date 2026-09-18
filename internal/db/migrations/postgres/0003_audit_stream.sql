-- Add the audit stream shipping key
--
-- The UUIDv7 id is generated at insert time, but a row written inside a transaction only becomes visible at commit time, so ordering by id would silently skip rows that commit after the shipper has already read past them
-- xact_id reflects commit visibility instead: a row is settled once its xact_id is below pg_snapshot_xmin(pg_current_snapshot()), the lowest still-running transaction id
--
-- The default is volatile, so this rewrites the table rather than taking the fast path for an added column
-- That is acceptable at up to 30 days of audit rows
-- Existing rows get an xid at or below the migrating transaction's, so they all count as settled immediately
ALTER TABLE v2_audit_events ADD COLUMN xact_id xid8 NOT NULL DEFAULT pg_current_xact_id();

CREATE INDEX IF NOT EXISTS idx_v2_audit_events_xact_id ON v2_audit_events (xact_id, id);

-- Generic key/value table for small pieces of application state
CREATE TABLE IF NOT EXISTS v2_kv (
	key text NOT NULL PRIMARY KEY,
	value text NOT NULL,
	-- Regenerated on every write
	etag text NOT NULL
);
