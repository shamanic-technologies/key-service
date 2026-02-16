import { describe, it, expect, beforeAll, beforeEach, afterAll } from "vitest";
import { eq } from "drizzle-orm";

describe("Keys Service Database", async () => {
  const { db, sql } = await import("../../src/db/index.js");
  const { orgs, apiKeys, appKeys, byokKeys } = await import("../../src/db/schema.js");
  const { cleanTestData, closeDb, insertTestOrg, insertTestApiKey, insertTestAppKey, insertTestByokKey } = await import("../helpers/test-db.js");

  beforeEach(async () => {
    await cleanTestData();
  });

  afterAll(async () => {
    await cleanTestData();
    await closeDb();
  });

  describe("orgs table", () => {
    it("should create and query an org", async () => {
      const org = await insertTestOrg({ clerkOrgId: "org_test123" });

      expect(org.id).toBeDefined();
      expect(org.clerkOrgId).toBe("org_test123");
    });
  });

  describe("apiKeys table", () => {
    it("should create an API key linked to org", async () => {
      const org = await insertTestOrg();
      const key = await insertTestApiKey(org.id, {
        keyHash: "abc123hash",
        keyPrefix: "mcpf_abc",
        name: "Production Key",
      });

      expect(key.id).toBeDefined();
      expect(key.keyHash).toBe("abc123hash");
      expect(key.keyPrefix).toBe("mcpf_abc");
    });

    it("should enforce unique keyHash", async () => {
      const org = await insertTestOrg();
      await insertTestApiKey(org.id, { keyHash: "unique_hash" });

      await expect(
        insertTestApiKey(org.id, { keyHash: "unique_hash" })
      ).rejects.toThrow();
    });

    it("should cascade delete when org is deleted", async () => {
      const org = await insertTestOrg();
      const key = await insertTestApiKey(org.id);

      await db.delete(orgs).where(eq(orgs.id, org.id));

      const found = await db.query.apiKeys.findFirst({
        where: eq(apiKeys.id, key.id),
      });
      expect(found).toBeUndefined();
    });
  });

  describe("byokKeys table", () => {
    it("should create a BYOK key linked to org", async () => {
      const org = await insertTestOrg();
      const key = await insertTestByokKey(org.id, {
        provider: "anthropic",
        encryptedKey: "encrypted_value",
      });

      expect(key.id).toBeDefined();
      expect(key.provider).toBe("anthropic");
    });

    it("should enforce unique org+provider", async () => {
      const org = await insertTestOrg();
      await insertTestByokKey(org.id, { provider: "apollo" });

      await expect(
        insertTestByokKey(org.id, { provider: "apollo" })
      ).rejects.toThrow();
    });

    it("should allow same provider for different orgs", async () => {
      const org1 = await insertTestOrg({ clerkOrgId: "org_1" });
      const org2 = await insertTestOrg({ clerkOrgId: "org_2" });

      await insertTestByokKey(org1.id, { provider: "apollo" });
      const key2 = await insertTestByokKey(org2.id, { provider: "apollo" });

      expect(key2.id).toBeDefined();
    });

    it("should cascade delete when org is deleted", async () => {
      const org = await insertTestOrg();
      const key = await insertTestByokKey(org.id);

      await db.delete(orgs).where(eq(orgs.id, org.id));

      const found = await db.query.byokKeys.findFirst({
        where: eq(byokKeys.id, key.id),
      });
      expect(found).toBeUndefined();
    });
  });

  describe("appKeys table", () => {
    it("should create an app key", async () => {
      const key = await insertTestAppKey({
        appId: "polaritycourse",
        provider: "stripe",
        encryptedKey: "encrypted_value",
      });

      expect(key.id).toBeDefined();
      expect(key.appId).toBe("polaritycourse");
      expect(key.provider).toBe("stripe");
    });

    it("should enforce unique appId+provider", async () => {
      await insertTestAppKey({ appId: "myapp", provider: "stripe" });

      await expect(
        insertTestAppKey({ appId: "myapp", provider: "stripe" })
      ).rejects.toThrow();
    });

    it("should allow same provider for different apps", async () => {
      await insertTestAppKey({ appId: "app1", provider: "stripe" });
      const key2 = await insertTestAppKey({ appId: "app2", provider: "stripe" });

      expect(key2.id).toBeDefined();
    });

    it("should allow different providers for same app", async () => {
      await insertTestAppKey({ appId: "myapp", provider: "stripe" });
      const key2 = await insertTestAppKey({ appId: "myapp", provider: "openai" });

      expect(key2.id).toBeDefined();
    });
  });
});
