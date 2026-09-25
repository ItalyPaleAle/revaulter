-- Which credentials the CLI can use to authenticate requests for this user
ALTER TABLE v2_users ADD COLUMN request_key_enabled INTEGER NOT NULL DEFAULT 1;
ALTER TABLE v2_users ADD COLUMN request_oidc_enabled INTEGER NOT NULL DEFAULT 0;

-- JSON array of the user's trusted OIDC issuers
ALTER TABLE v2_users ADD COLUMN request_oidc TEXT NOT NULL DEFAULT '[]';

-- SHA-256 of the per-request result token returned when the request is created
ALTER TABLE v2_requests ADD COLUMN result_token_hash TEXT NOT NULL DEFAULT '';
