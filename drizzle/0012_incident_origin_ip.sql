-- SECURITY-ALERTS-OURS-1128: the address the incident's first request came from, handed to
-- transactional-email-service with the alert so it decides whether the alert was caused by us.
ALTER TABLE "security_incidents" ADD COLUMN IF NOT EXISTS "origin_ip" text;
-- The reason transactional-email-service gave when it judged the alert caused by us (recorded, not
-- emailed). Null = an ordinary alert. Read by GET /internal/security/daily: ours are listed, never red.
ALTER TABLE "security_incidents" ADD COLUMN IF NOT EXISTS "ours_reason" text;
