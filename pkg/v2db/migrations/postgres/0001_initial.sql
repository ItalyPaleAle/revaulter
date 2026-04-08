CREATE TABLE IF NOT EXISTS v2_users (
	id text PRIMARY KEY,
	display_name text NOT NULL DEFAULT '',
	status text NOT NULL,
	webauthn_user_id text NOT NULL,
	password_canary text NOT NULL DEFAULT '',
	request_key text NOT NULL,
	request_enc_ecdh_pubkey text NOT NULL DEFAULT '',
	request_enc_mlkem_pubkey text NOT NULL DEFAULT '',
	allowed_ips text NOT NULL DEFAULT '',
	ready boolean NOT NULL DEFAULT false,
	created_at bigint NOT NULL,
	updated_at bigint NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_v2_users_webauthn_user_id ON v2_users(webauthn_user_id);

CREATE UNIQUE INDEX IF NOT EXISTS idx_v2_users_request_key ON v2_users(request_key);

CREATE TABLE IF NOT EXISTS v2_user_credentials (
	id text PRIMARY KEY,
	user_id text NOT NULL REFERENCES v2_users(id) ON DELETE CASCADE,
	credential_id text NOT NULL UNIQUE,
	public_key text NOT NULL,
	sign_count bigint NOT NULL,
	created_at bigint NOT NULL,
	last_used_at bigint NOT NULL
);

CREATE TABLE IF NOT EXISTS v2_auth_challenges (
	id text PRIMARY KEY,
	kind text NOT NULL,
	user_id text NOT NULL,
	challenge text NOT NULL,
	expires_at bigint NOT NULL,
	used_at bigint
);

CREATE TABLE IF NOT EXISTS v2_auth_challenge_payloads (
	challenge_id text PRIMARY KEY REFERENCES v2_auth_challenges(id) ON DELETE CASCADE,
	session_data text NOT NULL
);

CREATE TABLE IF NOT EXISTS v2_user_sessions (
	id text PRIMARY KEY,
	user_id text NOT NULL REFERENCES v2_users(id) ON DELETE CASCADE,
	expires_at bigint NOT NULL,
	created_at bigint NOT NULL,
	last_seen_at bigint NOT NULL,
	revoked_at bigint
);

CREATE INDEX IF NOT EXISTS idx_v2_auth_challenges_lookup ON v2_auth_challenges(kind, user_id, expires_at);

CREATE INDEX IF NOT EXISTS idx_v2_user_sessions_lookup ON v2_user_sessions(user_id, expires_at);

CREATE TABLE IF NOT EXISTS v2_requests (
	state text PRIMARY KEY,
	status text NOT NULL,
	operation text NOT NULL,
	user_id text NOT NULL REFERENCES v2_users(id) ON DELETE CASCADE,
	key_label text NOT NULL,
	algorithm text NOT NULL,
	requestor_ip text NOT NULL,
	note text NOT NULL,
	created_at bigint NOT NULL,
	expires_at bigint NOT NULL,
	updated_at bigint NOT NULL,
	encrypted_request text NOT NULL DEFAULT '',
	encrypted_result text NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_v2_requests_status_expires ON v2_requests(status, expires_at);

CREATE INDEX IF NOT EXISTS idx_v2_requests_user_status_created ON v2_requests(user_id, status, created_at);
