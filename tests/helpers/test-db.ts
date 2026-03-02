import { db, sql } from "../../src/db/index.js";
import { userAuthKeys, orgKeys, platformKeys, providers, orgProviderKeySources, providerRequirements } from "../../src/db/schema.js";

/**
 * Clean all test data from the database
 */
export async function cleanTestData() {
  await db.delete(userAuthKeys);
  await db.delete(orgProviderKeySources);
  await db.delete(orgKeys);
  await db.delete(platformKeys);
  await db.delete(providerRequirements);
  await db.delete(providers);
}

/**
 * Insert a test provider
 */
export async function insertTestProvider(data: { name?: string } = {}) {
  const [provider] = await db
    .insert(providers)
    .values({
      name: data.name || `provider-${Date.now()}`,
    })
    .returning();
  return provider;
}

/**
 * Insert a test user auth key
 */
export async function insertTestUserAuthKey(
  data: {
    orgId?: string;
    userId?: string;
    createdBy?: string;
    keyHash?: string;
    keyPrefix?: string;
    encryptedKey?: string;
    name?: string;
  } = {}
) {
  const [key] = await db
    .insert(userAuthKeys)
    .values({
      orgId: data.orgId || `test-org-${Date.now()}`,
      userId: data.userId || crypto.randomUUID(),
      createdBy: data.createdBy || crypto.randomUUID(),
      keyHash: data.keyHash || `hash-${Date.now()}-${Math.random()}`,
      keyPrefix: data.keyPrefix || "distrib.usr_",
      encryptedKey: data.encryptedKey,
      name: data.name || "Test Key",
    })
    .returning();
  return key;
}

/**
 * Insert a test org key
 */
export async function insertTestOrgKey(
  providerId: string,
  data: { orgId?: string; encryptedKey?: string } = {}
) {
  const [key] = await db
    .insert(orgKeys)
    .values({
      orgId: data.orgId || `test-org-${Date.now()}`,
      providerId,
      encryptedKey: data.encryptedKey || `encrypted-${Date.now()}`,
    })
    .returning();
  return key;
}

/**
 * Insert a test platform key
 */
export async function insertTestPlatformKey(
  providerId: string,
  data: { encryptedKey?: string } = {}
) {
  const [key] = await db
    .insert(platformKeys)
    .values({
      providerId,
      encryptedKey: data.encryptedKey || `encrypted-${Date.now()}`,
    })
    .returning();
  return key;
}

/**
 * Insert a test org provider key source preference
 */
export async function insertTestOrgProviderKeySource(
  data: { orgId?: string; providerId: string; keySource?: string }
) {
  const [pref] = await db
    .insert(orgProviderKeySources)
    .values({
      orgId: data.orgId || `test-org-${Date.now()}`,
      providerId: data.providerId,
      keySource: data.keySource || "platform",
    })
    .returning();
  return pref;
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
