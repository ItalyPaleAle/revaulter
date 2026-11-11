-- Credential type: 'passkey' for WebAuthn credentials registered in the web app, 'device' for Secure Enclave key sets registered by pairing a native app
-- For devices, public_key holds the JSON of the device's four public keys instead of a go-webauthn credential
ALTER TABLE v2_user_credentials ADD COLUMN credential_type text NOT NULL DEFAULT 'passkey';
