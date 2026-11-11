-- Status of each request, which changes from pending to a final status in the same transaction as the audit event that records it
ALTER TABLE v2_request_payloads ADD COLUMN status TEXT NOT NULL DEFAULT 'pending';
UPDATE v2_request_payloads SET status = 'completed' WHERE encrypted_result != '';
