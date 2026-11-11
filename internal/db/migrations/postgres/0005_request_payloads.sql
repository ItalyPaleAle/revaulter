-- Request metadata is kept in the revaulter.user actor, so the main database stores only the encrypted envelopes and the status
-- Requests in flight at upgrade time are discarded
DROP TABLE IF EXISTS v2_requests;

-- Encrypted envelopes and status of pending and recently finished requests, which are never included in backups
-- The status changes from pending to a final status in the same transaction as the audit event that records it
CREATE TABLE IF NOT EXISTS v2_request_payloads (
	state text PRIMARY KEY,
	user_id text NOT NULL REFERENCES v2_users(id) ON DELETE CASCADE,
	expires_at bigint NOT NULL,
	encrypted_request text NOT NULL,
	encrypted_result text NOT NULL DEFAULT '',
	status text NOT NULL DEFAULT 'pending'
);

CREATE INDEX IF NOT EXISTS idx_v2_request_payloads_expires_at ON v2_request_payloads(expires_at);
