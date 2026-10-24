-- Credential type: 'passkey' for WebAuthn credentials registered in the web app, 'device' for Secure Enclave key sets registered by pairing a native app
-- For devices, public_key holds the JSON of the device's four public keys instead of a go-webauthn credential
ALTER TABLE v2_user_credentials ADD COLUMN credential_type TEXT NOT NULL DEFAULT 'passkey';

-- Short-lived sessions that relay the pairing messages between an unlocked client and a new device
-- hello holds the device's hello as JSON; nonce and nonce_mac are set by the existing client after it accepts the hello
CREATE TABLE IF NOT EXISTS v2_pairing_sessions (
	id TEXT PRIMARY KEY,
	user_id TEXT NOT NULL REFERENCES v2_users(id) ON DELETE CASCADE,
	status TEXT NOT NULL,
	server TEXT NOT NULL,
	hello TEXT NOT NULL DEFAULT '',
	nonce TEXT NOT NULL DEFAULT '',
	nonce_mac TEXT NOT NULL DEFAULT '',
	created_at INTEGER NOT NULL,
	updated_at INTEGER NOT NULL,
	expires_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_v2_pairing_sessions_user_status ON v2_pairing_sessions(user_id, status);

CREATE INDEX IF NOT EXISTS idx_v2_pairing_sessions_expires ON v2_pairing_sessions(expires_at);
