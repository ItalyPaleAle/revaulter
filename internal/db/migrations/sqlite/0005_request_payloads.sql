-- Request metadata now lives in the revaulter.user actor in Francis, so only the encrypted envelopes stay in the main database
-- Requests in flight at upgrade time are discarded
DROP TABLE IF EXISTS v2_requests;

-- Encrypted envelopes of pending and recently finished requests
-- Rows are written and deleted only by the revaulter.user actor, and they are never included in backups
CREATE TABLE IF NOT EXISTS v2_request_payloads (
	state TEXT PRIMARY KEY,
	user_id TEXT NOT NULL REFERENCES v2_users(id) ON DELETE CASCADE,
	expires_at INTEGER NOT NULL,
	encrypted_request TEXT NOT NULL,
	encrypted_result TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_v2_request_payloads_expires_at ON v2_request_payloads(expires_at);
