CREATE TABLE IF NOT EXISTS v2_admins (
	id text PRIMARY KEY,
	username text NOT NULL UNIQUE,
	display_name text NOT NULL,
	status text NOT NULL,
	webauthn_user_id text NOT NULL DEFAULT '',
	password_canary text NOT NULL DEFAULT '',
	created_at bigint NOT NULL,
	updated_at bigint NOT NULL
);

CREATE TABLE IF NOT EXISTS v2_admin_credentials (
	id text PRIMARY KEY,
	admin_id text NOT NULL REFERENCES v2_admins(id) ON DELETE CASCADE,
	credential_id text NOT NULL UNIQUE,
	public_key text NOT NULL,
	sign_count bigint NOT NULL,
	created_at bigint NOT NULL,
	last_used_at bigint NOT NULL
);

CREATE TABLE IF NOT EXISTS v2_auth_challenges (
	id text PRIMARY KEY,
	kind text NOT NULL,
	username text NOT NULL,
	challenge text NOT NULL,
	expires_at bigint NOT NULL,
	used_at bigint
);

CREATE TABLE IF NOT EXISTS v2_auth_challenge_payloads (
	challenge_id text PRIMARY KEY REFERENCES v2_auth_challenges(id) ON DELETE CASCADE,
	session_data text NOT NULL
);

CREATE TABLE IF NOT EXISTS v2_admin_sessions (
	id text PRIMARY KEY,
	admin_id text NOT NULL REFERENCES v2_admins(id) ON DELETE CASCADE,
	username text NOT NULL,
	expires_at bigint NOT NULL,
	created_at bigint NOT NULL,
	last_seen_at bigint NOT NULL,
	revoked_at bigint
);

CREATE INDEX IF NOT EXISTS idx_v2_auth_challenges_lookup ON v2_auth_challenges(kind, username, expires_at);

CREATE INDEX IF NOT EXISTS idx_v2_admin_sessions_lookup ON v2_admin_sessions(username, expires_at);

CREATE TABLE IF NOT EXISTS v2_requests (
	state text PRIMARY KEY,
	status text NOT NULL,
	operation text NOT NULL,
	target_user text NOT NULL,
	key_label text NOT NULL,
	algorithm text NOT NULL,
	requestor_ip text NOT NULL,
	note text NOT NULL,
	created_at bigint NOT NULL,
	expires_at bigint NOT NULL,
	updated_at bigint NOT NULL,
	payload_ciphertext bytea NOT NULL,
	payload_nonce bytea NOT NULL,
	result_ciphertext bytea,
	result_nonce bytea
);

CREATE INDEX IF NOT EXISTS idx_v2_requests_status_expires ON v2_requests(status, expires_at);
