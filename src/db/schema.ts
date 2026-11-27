import { pgTable, uuid, text, timestamp, uniqueIndex, index, integer, boolean } from "drizzle-orm/pg-core";

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

// Brand keys — encrypted third-party API keys stored per org+brand+provider.
//
// A separate table from org_keys rather than a nullable brand_id column on it:
// org_keys' unique index is (org_id, provider_id), and widening it to include a
// nullable brand_id would change the collision rule every existing org-grain
// caller already relies on. Two brands of the same org can hold different
// credentials for the same provider here; the org-grain row keeps meaning
// exactly what it means today, and neither grain reads the other.
export const brandKeys = pgTable(
  "brand_keys",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    orgId: text("org_id").notNull(),
    brandId: text("brand_id").notNull(),
    providerId: uuid("provider_id")
      .notNull()
      .references(() => providers.id, { onDelete: "cascade" }),
    encryptedKey: text("encrypted_key").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    uniqueIndex("idx_brand_keys_org_brand_provider").on(
      table.orgId,
      table.brandId,
      table.providerId
    ),
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
export type BrandKey = typeof brandKeys.$inferSelect;
export type NewBrandKey = typeof brandKeys.$inferInsert;
export type PlatformKey = typeof platformKeys.$inferSelect;
export type NewPlatformKey = typeof platformKeys.$inferInsert;
export type OrgProviderKeySource = typeof orgProviderKeySources.$inferSelect;
export type NewOrgProviderKeySource = typeof orgProviderKeySources.$inferInsert;
export type ProviderRequirement = typeof providerRequirements.$inferSelect;
export type NewProviderRequirement = typeof providerRequirements.$inferInsert;

// Secret audit log (SECURITY-ALERTS-1128). One APPEND-ONLY row per decrypt,
// create, update or delete of a platform, org or brand key, and per request
// refused for a wrong service key. Never holds a key value. A migration trigger
// refuses UPDATE and refuses DELETE of rows younger than 90 days; the hourly
// retention sweep deletes what is older.
export const secretAuditEvents = pgTable(
  "secret_audit_events",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    action: text("action").notNull(), // decrypt | create | update | delete | auth_rejected
    grain: text("grain"), // platform | org | brand (null on auth_rejected)
    provider: text("provider"),
    orgId: text("org_id"),
    brandId: text("brand_id"),
    callerService: text("caller_service"),
    callerMethod: text("caller_method"),
    callerPath: text("caller_path"),
    requestMethod: text("request_method").notNull(),
    requestPath: text("request_path").notNull(),
    sourceIp: text("source_ip").notNull(),
    forwardedFor: text("forwarded_for"),
    outcome: text("outcome").notNull(), // success | not_found | refused
  },
  (table) => [
    index("idx_secret_audit_created").on(table.createdAt),
    index("idx_secret_audit_caller_created").on(table.callerService, table.createdAt),
    index("idx_secret_audit_ip_created").on(table.sourceIp, table.createdAt),
    index("idx_secret_audit_action_created").on(table.action, table.createdAt),
  ]
);

// Caller services that decrypted a key, with when each was last seen. A decrypt
// from a service absent here, or last seen more than 30 days ago, raises an
// unknown_caller_decrypt incident.
export const knownCallers = pgTable("known_callers", {
  service: text("service").primaryKey(),
  firstSeenAt: timestamp("first_seen_at", { withTimezone: true }).notNull().defaultNow(),
  lastSeenAt: timestamp("last_seen_at", { withTimezone: true }).notNull().defaultNow(),
});

// Security incidents: one row per (kind, subject) episode; a repeat within an
// hour of the last sighting joins the open episode instead of mailing again.
// The staff alert is sent once per incident, eventId `key-service:<kind>:<id>`.
export const securityIncidents = pgTable(
  "security_incidents",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    kind: text("kind").notNull(),
    subject: text("subject").notNull(),
    openedAt: timestamp("opened_at", { withTimezone: true }).notNull().defaultNow(),
    lastSeenAt: timestamp("last_seen_at", { withTimezone: true }).notNull().defaultNow(),
    eventCount: integer("event_count").notNull().default(1),
    summary: text("summary").notNull(),
    evidence: text("evidence").notNull(),
    test: boolean("test").notNull().default(false), // staff proof-of-fire: [TEST] subject, never red
    alertStatus: text("alert_status").notNull(), // pending | sent | failed
    alertAttempts: integer("alert_attempts").notNull().default(0),
    alertError: text("alert_error"),
    alertedAt: timestamp("alerted_at", { withTimezone: true }),
    // SECURITY-ALERTS-OURS-1128: where the first request came from (handed with the alert;
    // transactional-email-service decides whether the alert was caused by us).
    originIp: text("origin_ip"),
    oursReason: text("ours_reason"), // set when transactional-email judged it caused by us: not emailed, never red
  },
  (table) => [
    index("idx_security_incidents_kind_subject").on(table.kind, table.subject, table.lastSeenAt),
    index("idx_security_incidents_opened").on(table.openedAt),
  ]
);
