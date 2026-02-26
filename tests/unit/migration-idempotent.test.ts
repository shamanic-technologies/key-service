import { describe, it, expect } from "vitest";
import { readFileSync } from "fs";
import { join } from "path";
import { fileURLToPath } from "url";
import { dirname } from "path";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

describe("Migration 0004: rename clerk IDs", () => {
  const migrationPath = join(__dirname, "../../drizzle/0004_rename_clerk_ids.sql");
  const sql = readFileSync(migrationPath, "utf-8");

  it("should use conditional column renames (not bare ALTER TABLE RENAME)", () => {
    // The migration must handle the case where columns were already renamed
    // outside of Drizzle (e.g. manually in production). A bare RENAME COLUMN
    // would fail with "column clerk_org_id does not exist".
    expect(sql).not.toMatch(/^ALTER TABLE "orgs" RENAME COLUMN/m);
    expect(sql).not.toMatch(/^ALTER TABLE "users" RENAME COLUMN/m);
  });

  it("should wrap column renames in DO blocks with existence checks", () => {
    expect(sql).toContain("DO $$ BEGIN");
    expect(sql).toContain("IF EXISTS");
    expect(sql).toContain("column_name = 'clerk_org_id'");
    expect(sql).toContain("column_name = 'clerk_user_id'");
  });

  it("should use IF EXISTS / IF NOT EXISTS for index operations", () => {
    expect(sql).toContain('DROP INDEX IF EXISTS "idx_orgs_clerk_id"');
    expect(sql).toContain('DROP INDEX IF EXISTS "idx_users_clerk_id"');
    expect(sql).toContain('CREATE UNIQUE INDEX IF NOT EXISTS "idx_orgs_org_id"');
    expect(sql).toContain('CREATE UNIQUE INDEX IF NOT EXISTS "idx_users_user_id"');
  });
});
