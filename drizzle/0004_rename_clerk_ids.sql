DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'orgs' AND column_name = 'clerk_org_id') THEN
    ALTER TABLE "orgs" RENAME COLUMN "clerk_org_id" TO "org_id";
  END IF;
END $$;--> statement-breakpoint
DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'users' AND column_name = 'clerk_user_id') THEN
    ALTER TABLE "users" RENAME COLUMN "clerk_user_id" TO "user_id";
  END IF;
END $$;--> statement-breakpoint
DROP INDEX IF EXISTS "idx_orgs_clerk_id";--> statement-breakpoint
DROP INDEX IF EXISTS "idx_users_clerk_id";--> statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS "idx_orgs_org_id" ON "orgs" USING btree ("org_id");--> statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS "idx_users_user_id" ON "users" USING btree ("user_id");
