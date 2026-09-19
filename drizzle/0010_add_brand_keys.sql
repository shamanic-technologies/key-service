-- Brand-scoped third-party credentials.
--
-- One agency org holds many brands, each a different end client with its own
-- sub-account at the same provider. The org grain (org_keys, unique on
-- org_id + provider_id) cannot express that: two brands of one org collide.
--
-- Additive: org_keys is untouched, so every existing org-grain credential keeps
-- resolving exactly as it does today.
CREATE TABLE IF NOT EXISTS "brand_keys" (
  "id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
  "org_id" text NOT NULL,
  "brand_id" text NOT NULL,
  "provider_id" uuid NOT NULL REFERENCES "providers"("id") ON DELETE CASCADE,
  "encrypted_key" text NOT NULL,
  "created_at" timestamp with time zone DEFAULT now() NOT NULL,
  "updated_at" timestamp with time zone DEFAULT now() NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS "idx_brand_keys_org_brand_provider"
  ON "brand_keys" ("org_id", "brand_id", "provider_id");
