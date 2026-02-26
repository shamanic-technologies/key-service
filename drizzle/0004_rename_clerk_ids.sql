ALTER TABLE "orgs" RENAME COLUMN "clerk_org_id" TO "org_id";--> statement-breakpoint
ALTER TABLE "users" RENAME COLUMN "clerk_user_id" TO "user_id";--> statement-breakpoint
DROP INDEX IF EXISTS "idx_orgs_clerk_id";--> statement-breakpoint
DROP INDEX IF EXISTS "idx_users_clerk_id";--> statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS "idx_orgs_org_id" ON "orgs" USING btree ("org_id");--> statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS "idx_users_user_id" ON "users" USING btree ("user_id");
