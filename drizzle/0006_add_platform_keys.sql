CREATE TABLE IF NOT EXISTS "platform_keys" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"provider" text NOT NULL,
	"encrypted_key" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "platform_keys_provider_unique" UNIQUE("provider")
);
--> statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS "idx_platform_keys_provider" ON "platform_keys" USING btree ("provider");