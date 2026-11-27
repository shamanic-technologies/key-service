-- SECURITY-ALERTS-1128: durable trace of every secret read and write, plus the
-- incidents that mail staff. Additive: no existing table is touched.

CREATE TABLE IF NOT EXISTS "secret_audit_events" (
  "id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
  "created_at" timestamp with time zone DEFAULT now() NOT NULL,
  "action" text NOT NULL,
  "grain" text,
  "provider" text,
  "org_id" text,
  "brand_id" text,
  "caller_service" text,
  "caller_method" text,
  "caller_path" text,
  "request_method" text NOT NULL,
  "request_path" text NOT NULL,
  "source_ip" text NOT NULL,
  "forwarded_for" text,
  "outcome" text NOT NULL
);
CREATE INDEX IF NOT EXISTS "idx_secret_audit_created" ON "secret_audit_events" ("created_at");
CREATE INDEX IF NOT EXISTS "idx_secret_audit_caller_created" ON "secret_audit_events" ("caller_service", "created_at");
CREATE INDEX IF NOT EXISTS "idx_secret_audit_ip_created" ON "secret_audit_events" ("source_ip", "created_at");
CREATE INDEX IF NOT EXISTS "idx_secret_audit_action_created" ON "secret_audit_events" ("action", "created_at");

-- Append-only: no UPDATE ever; DELETE only of rows past the 90-day retention.
CREATE OR REPLACE FUNCTION "secret_audit_events_guard"() RETURNS trigger AS $$
BEGIN
  IF TG_OP = 'UPDATE' THEN
    RAISE EXCEPTION 'secret_audit_events is append-only';
  END IF;
  IF OLD.created_at > now() - interval '90 days' THEN
    RAISE EXCEPTION 'secret_audit_events rows are kept 90 days';
  END IF;
  RETURN OLD;
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS "secret_audit_events_append_only" ON "secret_audit_events";
CREATE TRIGGER "secret_audit_events_append_only"
  BEFORE UPDATE OR DELETE ON "secret_audit_events"
  FOR EACH ROW EXECUTE FUNCTION "secret_audit_events_guard"();

CREATE TABLE IF NOT EXISTS "known_callers" (
  "service" text PRIMARY KEY NOT NULL,
  "first_seen_at" timestamp with time zone DEFAULT now() NOT NULL,
  "last_seen_at" timestamp with time zone DEFAULT now() NOT NULL
);

-- The fleet's callers seen in the 30 days before this ship (provider_requirements,
-- prod 2026-11-27), minus the 2026-11-20 attacker names (probe26235, auto-collect,
-- probe) and one-off staff probes (secrets-rotate-1127, forensics-1127, x,
-- staff-setup): any of those decrypting again raises an alert.
INSERT INTO "known_callers" ("service") VALUES
  ('apollo'), ('brand'), ('chat'), ('chat-service'), ('client-service'),
  ('cloudflare-storage'), ('costs-service'), ('crm-service'), ('email-gateway'),
  ('expert-quotes-requests-service'), ('features-service'), ('google'), ('human'),
  ('instantly'), ('instantly-service'), ('lead'), ('meta'), ('postmark-service'),
  ('r2-private-mover'), ('runs-service'), ('scraping-service'), ('set-vendor-key'),
  ('social-service'), ('stripe'), ('transactional-email-service'), ('twilio-service')
ON CONFLICT DO NOTHING;

CREATE TABLE IF NOT EXISTS "security_incidents" (
  "id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
  "kind" text NOT NULL,
  "subject" text NOT NULL,
  "opened_at" timestamp with time zone DEFAULT now() NOT NULL,
  "last_seen_at" timestamp with time zone DEFAULT now() NOT NULL,
  "event_count" integer DEFAULT 1 NOT NULL,
  "summary" text NOT NULL,
  "evidence" text NOT NULL,
  "test" boolean DEFAULT false NOT NULL,
  "alert_status" text NOT NULL,
  "alert_attempts" integer DEFAULT 0 NOT NULL,
  "alert_error" text,
  "alerted_at" timestamp with time zone
);
CREATE INDEX IF NOT EXISTS "idx_security_incidents_kind_subject" ON "security_incidents" ("kind", "subject", "last_seen_at");
CREATE INDEX IF NOT EXISTS "idx_security_incidents_opened" ON "security_incidents" ("opened_at");
