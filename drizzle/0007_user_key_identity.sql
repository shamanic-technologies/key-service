-- Migration: Add app_id, user_id, created_by to api_keys
-- Delete all existing user keys (old mcpf_* prefix) since we're changing the schema.
-- New keys will use mcpf_usr_* prefix.

DELETE FROM "api_keys";

ALTER TABLE "api_keys" ADD COLUMN "app_id" text NOT NULL;
ALTER TABLE "api_keys" ADD COLUMN "user_id" uuid NOT NULL;
ALTER TABLE "api_keys" ADD COLUMN "created_by" uuid NOT NULL;
