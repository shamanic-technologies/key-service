import { pgTable, uuid, text, timestamp, uniqueIndex } from "drizzle-orm/pg-core";

// Local users table (maps to client-service)
export const users = pgTable(
  "users",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    userId: text("user_id").notNull().unique(),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    uniqueIndex("idx_users_user_id").on(table.userId),
  ]
);

// Local orgs table (maps to client-service)
export const orgs = pgTable(
  "orgs",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    orgId: text("org_id").notNull().unique(),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    uniqueIndex("idx_orgs_org_id").on(table.orgId),
  ]
);

// API keys for org authentication
export const apiKeys = pgTable(
  "api_keys",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    orgId: uuid("org_id")
      .notNull()
      .references(() => orgs.id, { onDelete: "cascade" }),
    keyHash: text("key_hash").notNull().unique(),
    keyPrefix: text("key_prefix").notNull(), // First 8 chars for display
    encryptedKey: text("encrypted_key"), // AES-256-GCM encrypted raw key for retrieval
    name: text("name"),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    lastUsedAt: timestamp("last_used_at", { withTimezone: true }),
  },
  (table) => [
    uniqueIndex("idx_api_keys_hash").on(table.keyHash),
  ]
);

// BYOK keys (encrypted external API keys)
export const byokKeys = pgTable(
  "byok_keys",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    orgId: uuid("org_id")
      .notNull()
      .references(() => orgs.id, { onDelete: "cascade" }),
    provider: text("provider").notNull(), // 'apollo', 'anthropic', 'instantly', 'firecrawl'
    encryptedKey: text("encrypted_key").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    uniqueIndex("idx_byok_org_provider").on(table.orgId, table.provider),
  ]
);

export type User = typeof users.$inferSelect;
export type NewUser = typeof users.$inferInsert;
export type Org = typeof orgs.$inferSelect;
export type NewOrg = typeof orgs.$inferInsert;
export type ApiKey = typeof apiKeys.$inferSelect;
export type NewApiKey = typeof apiKeys.$inferInsert;
export type ByokKey = typeof byokKeys.$inferSelect;
export type NewByokKey = typeof byokKeys.$inferInsert;

// App keys (encrypted third-party API keys for apps, keyed by appId)
export const appKeys = pgTable(
  "app_keys",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    appId: text("app_id").notNull(),
    provider: text("provider").notNull(),
    encryptedKey: text("encrypted_key").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    uniqueIndex("idx_app_keys_app_provider").on(table.appId, table.provider),
  ]
);

export type AppKey = typeof appKeys.$inferSelect;
export type NewAppKey = typeof appKeys.$inferInsert;

// Provider requirements registry (auto-discovered from decrypt calls)
export const providerRequirements = pgTable(
  "provider_requirements",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    service: text("service").notNull(),
    method: text("method").notNull(),
    path: text("path").notNull(),
    provider: text("provider").notNull(),
    lastSeenAt: timestamp("last_seen_at", { withTimezone: true }).notNull().defaultNow(),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    uniqueIndex("idx_provider_req_unique").on(
      table.service,
      table.method,
      table.path,
      table.provider
    ),
  ]
);

export type ProviderRequirement = typeof providerRequirements.$inferSelect;
export type NewProviderRequirement = typeof providerRequirements.$inferInsert;

// Registered apps (each app gets an API key to authenticate with the platform)
export const apps = pgTable(
  "apps",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    name: text("name").notNull(),
    keyHash: text("key_hash").notNull(),
    keyPrefix: text("key_prefix").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    uniqueIndex("idx_apps_name").on(table.name),
    uniqueIndex("idx_apps_key_hash").on(table.keyHash),
  ]
);

export type App = typeof apps.$inferSelect;
export type NewApp = typeof apps.$inferInsert;
