-- Version of the pubkey bundle signature stored on the user row
-- 1 = legacy payload that binds wrappedKeyEpoch (always signed as 1 at signup); 2 = payload that binds an explicit `v` line instead
-- Existing rows were all signed with the legacy payload, hence the default
ALTER TABLE v2_users ADD COLUMN pubkey_bundle_version bigint NOT NULL DEFAULT 1;
