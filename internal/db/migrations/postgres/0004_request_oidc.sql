-- Which credentials the CLI can use to authenticate requests for this user
ALTER TABLE v2_users ADD COLUMN request_key_enabled boolean NOT NULL DEFAULT true;
ALTER TABLE v2_users ADD COLUMN request_oidc_enabled boolean NOT NULL DEFAULT false;

-- JSON array of the user's trusted OIDC issuers
ALTER TABLE v2_users ADD COLUMN request_oidc jsonb NOT NULL DEFAULT '[]'::jsonb;

-- SHA-256 of the per-request result token returned when the request is created
ALTER TABLE v2_requests ADD COLUMN result_token_hash text NOT NULL DEFAULT '';
