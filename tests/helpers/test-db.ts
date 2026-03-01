import { db, sql } from "../../src/db/index.js";
import { orgs, users, apiKeys, appKeys, apps, byokKeys, platformKeys, providerRequirements } from "../../src/db/schema.js";

/**
 * Clean all test data from the database
 */
export async function cleanTestData() {
  await db.delete(apiKeys);
  await db.delete(appKeys);
  await db.delete(platformKeys);
  await db.delete(byokKeys);
  await db.delete(providerRequirements);
  await db.delete(apps);
  await db.delete(users);
  await db.delete(orgs);
}

/**
 * Insert a test org
 */
export async function insertTestOrg(data: { orgId?: string } = {}) {
  const [org] = await db
    .insert(orgs)
    .values({
      orgId: data.orgId || `test-org-${Date.now()}`,
    })
    .returning();
  return org;
}

/**
 * Insert a test user
 */
export async function insertTestUser(data: { userId?: string } = {}) {
  const [user] = await db
    .insert(users)
    .values({
      userId: data.userId || `test-user-${Date.now()}`,
    })
    .returning();
  return user;
}

/**
 * Insert a test API key
 */
export async function insertTestApiKey(
  orgId: string,
  data: {
    appId?: string;
    userId?: string;
    createdBy?: string;
    keyHash?: string;
    keyPrefix?: string;
    encryptedKey?: string;
    name?: string;
  } = {}
) {
  const [key] = await db
    .insert(apiKeys)
    .values({
      appId: data.appId || "test-app",
      orgId,
      userId: data.userId || crypto.randomUUID(),
      createdBy: data.createdBy || crypto.randomUUID(),
      keyHash: data.keyHash || `hash-${Date.now()}`,
      keyPrefix: data.keyPrefix || "mcpf_usr_tes",
      encryptedKey: data.encryptedKey,
      name: data.name || "Test Key",
    })
    .returning();
  return key;
}

/**
 * Insert a test BYOK key
 */
export async function insertTestByokKey(
  orgId: string,
  data: { provider?: string; encryptedKey?: string } = {}
) {
  const [key] = await db
    .insert(byokKeys)
    .values({
      orgId,
      provider: data.provider || "apollo",
      encryptedKey: data.encryptedKey || `encrypted-${Date.now()}`,
    })
    .returning();
  return key;
}

/**
 * Insert a test app key
 */
export async function insertTestAppKey(
  data: { appId?: string; provider?: string; encryptedKey?: string } = {}
) {
  const [key] = await db
    .insert(appKeys)
    .values({
      appId: data.appId || `test-app-${Date.now()}`,
      provider: data.provider || "stripe",
      encryptedKey: data.encryptedKey || `encrypted-${Date.now()}`,
    })
    .returning();
  return key;
}

/**
 * Insert a test platform key
 */
export async function insertTestPlatformKey(
  data: { provider?: string; encryptedKey?: string } = {}
) {
  const [key] = await db
    .insert(platformKeys)
    .values({
      provider: data.provider || "anthropic",
      encryptedKey: data.encryptedKey || `encrypted-${Date.now()}`,
    })
    .returning();
  return key;
}

/**
 * Insert a test provider requirement
 */
export async function insertTestProviderRequirement(
  data: { service?: string; method?: string; path?: string; provider?: string } = {}
) {
  const [req] = await db
    .insert(providerRequirements)
    .values({
      service: data.service || "apollo",
      method: data.method || "POST",
      path: data.path || "/leads/search",
      provider: data.provider || "apollo",
    })
    .returning();
  return req;
}

/**
 * Close database connection
 */
export async function closeDb() {
  await sql.end();
}

/**
 * Generate a random UUID
 */
export function randomId(): string {
  return crypto.randomUUID();
}
