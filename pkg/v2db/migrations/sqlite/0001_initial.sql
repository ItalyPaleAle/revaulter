CREATE TABLE IF NOT EXISTS v2_admins (
	id TEXT PRIMARY KEY,
	username TEXT NOT NULL UNIQUE,
	display_name TEXT NOT NULL,
	status TEXT NOT NULL,
	webauthn_user_id TEXT NOT NULL DEFAULT '',
	password_canary TEXT NOT NULL DEFAULT '',
	created_at INTEGER NOT NULL,
	updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS v2_admin_credentials (
	id TEXT PRIMARY KEY,
	admin_id TEXT NOT NULL REFERENCES v2_admins(id) ON DELETE CASCADE,
	credential_id TEXT NOT NULL UNIQUE,
	public_key TEXT NOT NULL,
	sign_count INTEGER NOT NULL,
	created_at INTEGER NOT NULL,
	last_used_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS v2_auth_challenges (
	id TEXT PRIMARY KEY,
	kind TEXT NOT NULL,
	username TEXT NOT NULL,
	challenge TEXT NOT NULL,
	expires_at INTEGER NOT NULL,
	used_at INTEGER
);

CREATE TABLE IF NOT EXISTS v2_auth_challenge_payloads (
	challenge_id TEXT PRIMARY KEY REFERENCES v2_auth_challenges(id) ON DELETE CASCADE,
	session_data TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS v2_admin_sessions (
	id TEXT PRIMARY KEY,
	admin_id TEXT NOT NULL REFERENCES v2_admins(id) ON DELETE CASCADE,
	username TEXT NOT NULL,
	expires_at INTEGER NOT NULL,
	created_at INTEGER NOT NULL,
	last_seen_at INTEGER NOT NULL,
	revoked_at INTEGER
);

CREATE INDEX IF NOT EXISTS idx_v2_auth_challenges_lookup ON v2_auth_challenges(kind, username, expires_at);

CREATE INDEX IF NOT EXISTS idx_v2_admin_sessions_lookup ON v2_admin_sessions(username, expires_at);

CREATE TABLE IF NOT EXISTS v2_requests (
	state TEXT PRIMARY KEY,
	status TEXT NOT NULL,
	operation TEXT NOT NULL,
	target_user TEXT NOT NULL,
	key_label TEXT NOT NULL,
	algorithm TEXT NOT NULL,
	requestor_ip TEXT NOT NULL,
	note TEXT NOT NULL,
	created_at INTEGER NOT NULL,
	expires_at INTEGER NOT NULL,
	updated_at INTEGER NOT NULL,
	payload_ciphertext BLOB NOT NULL,
	payload_nonce BLOB NOT NULL,
	result_ciphertext BLOB,
	result_nonce BLOB
);

CREATE INDEX IF NOT EXISTS idx_v2_requests_status_expires ON v2_requests(status, expires_at);
