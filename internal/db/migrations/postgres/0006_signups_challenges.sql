-- WebAuthn challenges and unfinished signups are kept in the revaulter.challenge and revaulter.signup actors
DELETE FROM v2_user_credentials WHERE user_id IN (SELECT id FROM v2_users WHERE ready = false);
DELETE FROM v2_published_signing_keys WHERE user_id IN (SELECT id FROM v2_users WHERE ready = false);
DELETE FROM v2_request_payloads WHERE user_id IN (SELECT id FROM v2_users WHERE ready = false);
DELETE FROM v2_users WHERE ready = false;

DROP TABLE IF EXISTS v2_auth_challenge_payloads;
DROP TABLE IF EXISTS v2_auth_challenges;
