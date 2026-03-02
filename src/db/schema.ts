import { pgTable, uuid, text, timestamp, uniqueIndex } from "drizzle-orm/pg-core";

// Provider registry — canonical list of valid provider names
export const providers = pgTable(
  "providers",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    name: text("name").notNull().unique(),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    uniqueIndex("idx_providers_name").on(table.name),
  ]
);

// User auth keys — tokens for user authentication (distrib.usr_*)
export const userAuthKeys = pgTable(
  "user_auth_keys",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    orgId: text("org_id").notNull(),
    userId: text("user_id").notNull(),
    createdBy: text("created_by").notNull(),
    keyHash: text("key_hash").notNull().unique(),
    keyPrefix: text("key_prefix").notNull(),
    encryptedKey: text("encrypted_key"),
    name: text("name"),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    lastUsedAt: timestamp("last_used_at", { withTimezone: true }),
  },
  (table) => [
    uniqueIndex("idx_api_keys_hash").on(table.keyHash),
  ]
);

// Org keys — encrypted third-party API keys stored per org+provider
export const orgKeys = pgTable(
  "org_keys",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    orgId: text("org_id").notNull(),
    providerId: uuid("provider_id")
      .notNull()
      .references(() => providers.id, { onDelete: "cascade" }),
    encryptedKey: text("encrypted_key").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    uniqueIndex("idx_org_keys_org_provider").on(table.orgId, table.providerId),
  ]
);

// Platform keys — encrypted third-party API keys for the platform (global, one per provider)
export const platformKeys = pgTable(
  "platform_keys",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    providerId: uuid("provider_id")
      .notNull()
      .unique()
      .references(() => providers.id, { onDelete: "cascade" }),
    encryptedKey: text("encrypted_key").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    uniqueIndex("idx_platform_keys_provider").on(table.providerId),
  ]
);

// Org provider key sources — per org+provider preference: "org" or "platform"
// Default (no row) = "platform"
export const orgProviderKeySources = pgTable(
  "org_provider_key_sources",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    orgId: text("org_id").notNull(),
    providerId: uuid("provider_id")
      .notNull()
      .references(() => providers.id, { onDelete: "cascade" }),
    keySource: text("key_source").notNull(), // "org" | "platform"
    updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    uniqueIndex("idx_org_provider_key_sources").on(table.orgId, table.providerId),
  ]
);

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

export type Provider = typeof providers.$inferSelect;
export type NewProvider = typeof providers.$inferInsert;
export type UserAuthKey = typeof userAuthKeys.$inferSelect;
export type NewUserAuthKey = typeof userAuthKeys.$inferInsert;
export type OrgKey = typeof orgKeys.$inferSelect;
export type NewOrgKey = typeof orgKeys.$inferInsert;
export type PlatformKey = typeof platformKeys.$inferSelect;
export type NewPlatformKey = typeof platformKeys.$inferInsert;
export type OrgProviderKeySource = typeof orgProviderKeySources.$inferSelect;
export type NewOrgProviderKeySource = typeof orgProviderKeySources.$inferInsert;
export type ProviderRequirement = typeof providerRequirements.$inferSelect;
export type NewProviderRequirement = typeof providerRequirements.$inferInsert;
