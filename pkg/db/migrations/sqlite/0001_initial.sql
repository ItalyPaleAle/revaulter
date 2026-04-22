CREATE TABLE IF NOT EXISTS v2_users (
	id TEXT PRIMARY KEY,
	display_name TEXT NOT NULL DEFAULT '',
	status TEXT NOT NULL,
	webauthn_user_id TEXT NOT NULL,
	request_key TEXT NOT NULL,
	request_enc_ecdh_pubkey TEXT NOT NULL DEFAULT '',
	request_enc_mlkem_pubkey TEXT NOT NULL DEFAULT '',
	anchor_es384_public_key TEXT NOT NULL DEFAULT '',
	anchor_mldsa87_public_key TEXT NOT NULL DEFAULT '',
	pubkey_bundle_signature_es384 TEXT NOT NULL DEFAULT '',
	pubkey_bundle_signature_mldsa87 TEXT NOT NULL DEFAULT '',
	wrapped_key_epoch INTEGER NOT NULL DEFAULT 1,
	allowed_ips TEXT NOT NULL DEFAULT '',
	ready INTEGER NOT NULL DEFAULT 0,
	created_at INTEGER NOT NULL,
	updated_at INTEGER NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_v2_users_webauthn_user_id ON v2_users(webauthn_user_id);

CREATE UNIQUE INDEX IF NOT EXISTS idx_v2_users_request_key ON v2_users(request_key);

CREATE TABLE IF NOT EXISTS v2_user_credentials (
	id TEXT PRIMARY KEY,
	user_id TEXT NOT NULL REFERENCES v2_users(id) ON DELETE CASCADE,
	credential_id TEXT NOT NULL UNIQUE,
	display_name TEXT NOT NULL DEFAULT '',
	public_key TEXT NOT NULL,
	sign_count INTEGER NOT NULL,
	wrapped_primary_key TEXT NOT NULL DEFAULT '',
	wrapped_anchor_key TEXT NOT NULL DEFAULT '',
	attestation_payload TEXT NOT NULL DEFAULT '',
	attestation_signature_es384 TEXT NOT NULL DEFAULT '',
	attestation_signature_mldsa87 TEXT NOT NULL DEFAULT '',
	wrapped_key_epoch INTEGER NOT NULL DEFAULT 1,
	created_at INTEGER NOT NULL,
	last_used_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS v2_auth_challenges (
	id TEXT PRIMARY KEY,
	kind TEXT NOT NULL,
	user_id TEXT NOT NULL,
	challenge TEXT NOT NULL,
	expires_at INTEGER NOT NULL,
	used_at INTEGER
);

CREATE TABLE IF NOT EXISTS v2_auth_challenge_payloads (
	challenge_id TEXT PRIMARY KEY REFERENCES v2_auth_challenges(id) ON DELETE CASCADE,
	session_data TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS v2_requests (
	state TEXT PRIMARY KEY,
	status TEXT NOT NULL,
	operation TEXT NOT NULL,
	user_id TEXT NOT NULL REFERENCES v2_users(id) ON DELETE CASCADE,
	key_label TEXT NOT NULL,
	algorithm TEXT NOT NULL,
	requestor_ip TEXT NOT NULL,
	note TEXT NOT NULL,
	created_at INTEGER NOT NULL,
	expires_at INTEGER NOT NULL,
	updated_at INTEGER NOT NULL,
	encrypted_request TEXT NOT NULL DEFAULT '',
	encrypted_result TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_v2_requests_status_expires ON v2_requests(status, expires_at);

CREATE INDEX IF NOT EXISTS idx_v2_requests_user_status_created ON v2_requests(user_id, status, created_at);

CREATE TABLE IF NOT EXISTS v2_published_signing_keys (
	id TEXT PRIMARY KEY,
	user_id TEXT NOT NULL REFERENCES v2_users(id) ON DELETE CASCADE,
	algorithm TEXT NOT NULL,
	key_label TEXT NOT NULL,
	jwk TEXT NOT NULL,
	pem TEXT NOT NULL,
	published INTEGER NOT NULL DEFAULT 0,
	created_at INTEGER NOT NULL,
	updated_at INTEGER NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_v2_published_signing_keys_user_alg_label ON v2_published_signing_keys(user_id, algorithm, key_label);
