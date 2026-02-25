CREATE TABLE IF NOT EXISTS "provider_requirements" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"service" text NOT NULL,
	"method" text NOT NULL,
	"path" text NOT NULL,
	"provider" text NOT NULL,
	"last_seen_at" timestamp with time zone DEFAULT now() NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS "idx_provider_req_unique" ON "provider_requirements" USING btree ("service","method","path","provider");