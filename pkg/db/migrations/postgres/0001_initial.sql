CREATE TABLE IF NOT EXISTS v2_users (
	id text PRIMARY KEY,
	display_name text NOT NULL DEFAULT '',
	status text NOT NULL,
	webauthn_user_id text NOT NULL,
	request_key text NOT NULL,
	request_enc_ecdh_pubkey text NOT NULL DEFAULT '',
	request_enc_mlkem_pubkey text NOT NULL DEFAULT '',
	anchor_es384_public_key text NOT NULL DEFAULT '',
	anchor_mldsa87_public_key text NOT NULL DEFAULT '',
	pubkey_bundle_signature_es384 text NOT NULL DEFAULT '',
	pubkey_bundle_signature_mldsa87 text NOT NULL DEFAULT '',
	wrapped_key_epoch bigint NOT NULL DEFAULT 1,
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
	display_name text NOT NULL DEFAULT '',
	public_key text NOT NULL,
	sign_count bigint NOT NULL,
	wrapped_primary_key text NOT NULL DEFAULT '',
	wrapped_anchor_key text NOT NULL DEFAULT '',
	attestation_payload text NOT NULL DEFAULT '',
	attestation_signature_es384 text NOT NULL DEFAULT '',
	attestation_signature_mldsa87 text NOT NULL DEFAULT '',
	wrapped_key_epoch bigint NOT NULL DEFAULT 1,
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

CREATE TABLE IF NOT EXISTS v2_published_signing_keys (
	id text PRIMARY KEY,
	user_id text NOT NULL REFERENCES v2_users(id) ON DELETE CASCADE,
	algorithm text NOT NULL,
	key_label text NOT NULL,
	jwk text NOT NULL,
	pem text NOT NULL,
	published boolean NOT NULL DEFAULT false,
	publication_payload text NOT NULL DEFAULT '',
	publication_signature_es384 text NOT NULL DEFAULT '',
	publication_signature_mldsa87 text NOT NULL DEFAULT '',
	created_at bigint NOT NULL,
	updated_at bigint NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_v2_published_signing_keys_user_alg_label ON v2_published_signing_keys(user_id, algorithm, key_label);
