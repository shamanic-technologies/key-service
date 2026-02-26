import { migrate } from "drizzle-orm/postgres-js/migrator";
import { drizzle } from "drizzle-orm/postgres-js";
import postgres from "postgres";

/**
 * Vitest globalSetup: resets key-service tables and runs all migrations
 * from scratch for a clean, reproducible test state.
 * Works with any Postgres (local or Neon branch) — just set KEY_SERVICE_DATABASE_URL.
 */
export default async function setup() {
  const url = process.env.KEY_SERVICE_DATABASE_URL || "postgresql://test:test@localhost/test";
  const sql = postgres(url);

  // Drop key-service tables (FK-safe order) and migration tracking
  await sql.unsafe(`
    DROP TABLE IF EXISTS provider_requirements CASCADE;
    DROP TABLE IF EXISTS app_keys CASCADE;
    DROP TABLE IF EXISTS byok_keys CASCADE;
    DROP TABLE IF EXISTS api_keys CASCADE;
    DROP TABLE IF EXISTS users CASCADE;
    DROP TABLE IF EXISTS orgs CASCADE;
    DROP SCHEMA IF EXISTS drizzle CASCADE;
  `);

  // Apply all migrations from scratch
  const db = drizzle(sql);
  await migrate(db, { migrationsFolder: "./drizzle" });
  await sql.end();
}
