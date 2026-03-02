-- Migration: Remove appId concept, add providers table, add org_provider_key_sources
-- This is a major schema refactor:
-- 1. Creates providers registry table
-- 2. Creates org_provider_key_sources for per-org per-provider key source preference
-- 3. Renames api_keys → user_auth_keys, drops appId, converts org_id to text
-- 4. Converts org_keys and platform_keys to use provider_id FK
-- 5. Drops app_keys, apps, users, orgs tables

-- 1. Create providers table
CREATE TABLE "providers" (
  "id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
  "name" text NOT NULL UNIQUE,
  "created_at" timestamp with time zone DEFAULT now() NOT NULL
);
CREATE UNIQUE INDEX "idx_providers_name" ON "providers" ("name");

-- 2. Seed providers from existing data across all tables
INSERT INTO "providers" ("name")
SELECT DISTINCT provider FROM (
  SELECT provider FROM "org_keys"
  UNION SELECT provider FROM "platform_keys"
  UNION SELECT provider FROM "app_keys"
  UNION SELECT provider FROM "provider_requirements"
) AS all_providers
ON CONFLICT DO NOTHING;

-- 3. Create org_provider_key_sources table
CREATE TABLE "org_provider_key_sources" (
  "id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
  "org_id" text NOT NULL,
  "provider_id" uuid NOT NULL REFERENCES "providers"("id") ON DELETE CASCADE,
  "key_source" text NOT NULL CHECK ("key_source" IN ('org', 'platform')),
  "updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
CREATE UNIQUE INDEX "idx_org_provider_key_sources" ON "org_provider_key_sources" ("org_id", "provider_id");

-- 4. Transform api_keys → user_auth_keys
ALTER TABLE "api_keys" RENAME TO "user_auth_keys";

-- Convert org_id from uuid FK to text (resolving through orgs table)
ALTER TABLE "user_auth_keys" ADD COLUMN "org_id_text" text;
UPDATE "user_auth_keys" SET "org_id_text" = o."org_id" FROM "orgs" o WHERE "user_auth_keys"."org_id" = o."id";
ALTER TABLE "user_auth_keys" DROP CONSTRAINT IF EXISTS "api_keys_org_id_orgs_id_fk";
ALTER TABLE "user_auth_keys" DROP COLUMN "org_id";
ALTER TABLE "user_auth_keys" RENAME COLUMN "org_id_text" TO "org_id";
ALTER TABLE "user_auth_keys" ALTER COLUMN "org_id" SET NOT NULL;

-- Drop appId column
ALTER TABLE "user_auth_keys" DROP COLUMN "app_id";

-- Convert user_id and created_by from uuid to text
ALTER TABLE "user_auth_keys" ALTER COLUMN "user_id" TYPE text USING "user_id"::text;
ALTER TABLE "user_auth_keys" ALTER COLUMN "created_by" TYPE text USING "created_by"::text;

-- 5. Transform org_keys
ALTER TABLE "org_keys" ADD COLUMN "org_id_text" text;
ALTER TABLE "org_keys" ADD COLUMN "provider_id" uuid;
UPDATE "org_keys" SET "org_id_text" = o."org_id" FROM "orgs" o WHERE "org_keys"."org_id" = o."id";
UPDATE "org_keys" SET "provider_id" = p."id" FROM "providers" p WHERE "org_keys"."provider" = p."name";
ALTER TABLE "org_keys" DROP CONSTRAINT IF EXISTS "byok_keys_org_id_orgs_id_fk";
DROP INDEX IF EXISTS "idx_org_keys_org_provider";
ALTER TABLE "org_keys" DROP COLUMN "org_id";
ALTER TABLE "org_keys" DROP COLUMN "provider";
ALTER TABLE "org_keys" RENAME COLUMN "org_id_text" TO "org_id";
ALTER TABLE "org_keys" ALTER COLUMN "org_id" SET NOT NULL;
ALTER TABLE "org_keys" ALTER COLUMN "provider_id" SET NOT NULL;
ALTER TABLE "org_keys" ADD CONSTRAINT "org_keys_provider_id_fk" FOREIGN KEY ("provider_id") REFERENCES "providers"("id") ON DELETE CASCADE;
CREATE UNIQUE INDEX "idx_org_keys_org_provider" ON "org_keys" ("org_id", "provider_id");

-- 6. Transform platform_keys
ALTER TABLE "platform_keys" ADD COLUMN "provider_id" uuid;
UPDATE "platform_keys" SET "provider_id" = p."id" FROM "providers" p WHERE "platform_keys"."provider" = p."name";
DROP INDEX IF EXISTS "idx_platform_keys_provider";
ALTER TABLE "platform_keys" DROP COLUMN "provider";
ALTER TABLE "platform_keys" ALTER COLUMN "provider_id" SET NOT NULL;
ALTER TABLE "platform_keys" ADD CONSTRAINT "platform_keys_provider_id_fk" FOREIGN KEY ("provider_id") REFERENCES "providers"("id") ON DELETE CASCADE;
CREATE UNIQUE INDEX "idx_platform_keys_provider" ON "platform_keys" ("provider_id");

-- 7. Drop removed tables
DROP TABLE IF EXISTS "app_keys";
DROP TABLE IF EXISTS "apps";
DROP TABLE IF EXISTS "users";
DROP TABLE IF EXISTS "orgs";
