import { describe, it, expect, beforeEach, afterAll } from "vitest";
import { eq } from "drizzle-orm";

describe("Keys Service Database", async () => {
  const { db, sql } = await import("../../src/db/index.js");
  const { providers, userAuthKeys, orgKeys, platformKeys, orgProviderKeySources, providerRequirements } = await import("../../src/db/schema.js");
  const {
    cleanTestData,
    closeDb,
    insertTestProvider,
    insertTestUserAuthKey,
    insertTestOrgKey,
    insertTestPlatformKey,
    insertTestOrgProviderKeySource,
    insertTestProviderRequirement,
  } = await import("../helpers/test-db.js");

  beforeEach(async () => {
    await cleanTestData();
  });

  afterAll(async () => {
    await cleanTestData();
    await closeDb();
  });

  describe("providers table", () => {
    it("should create a provider", async () => {
      const provider = await insertTestProvider({ name: "anthropic" });

      expect(provider.id).toBeDefined();
      expect(provider.name).toBe("anthropic");
    });

    it("should enforce unique name", async () => {
      await insertTestProvider({ name: "anthropic" });

      await expect(
        insertTestProvider({ name: "anthropic" })
      ).rejects.toThrow();
    });
  });

  describe("userAuthKeys table", () => {
    it("should create a user auth key", async () => {
      const key = await insertTestUserAuthKey({
        orgId: "org-test-123",
        keyHash: "abc123hash",
        keyPrefix: "distrib.usr_",
        name: "Production Key",
      });

      expect(key.id).toBeDefined();
      expect(key.orgId).toBe("org-test-123");
      expect(key.keyHash).toBe("abc123hash");
      expect(key.keyPrefix).toBe("distrib.usr_");
    });

    it("should enforce unique keyHash", async () => {
      await insertTestUserAuthKey({ keyHash: "unique_hash" });

      await expect(
        insertTestUserAuthKey({ keyHash: "unique_hash" })
      ).rejects.toThrow();
    });

    it("should store orgId as text (not FK)", async () => {
      const key = await insertTestUserAuthKey({ orgId: "any-string-org-id" });

      expect(key.orgId).toBe("any-string-org-id");
    });
  });

  describe("orgKeys table", () => {
    it("should create an org key linked to provider", async () => {
      const provider = await insertTestProvider({ name: "anthropic" });
      const key = await insertTestOrgKey(provider.id, {
        orgId: "org-test",
        encryptedKey: "encrypted_value",
      });

      expect(key.id).toBeDefined();
      expect(key.orgId).toBe("org-test");
      expect(key.providerId).toBe(provider.id);
    });

    it("should enforce unique org+provider", async () => {
      const provider = await insertTestProvider({ name: "apollo" });
      await insertTestOrgKey(provider.id, { orgId: "org-1" });

      await expect(
        insertTestOrgKey(provider.id, { orgId: "org-1" })
      ).rejects.toThrow();
    });

    it("should allow same provider for different orgs", async () => {
      const provider = await insertTestProvider({ name: "apollo" });
      await insertTestOrgKey(provider.id, { orgId: "org-1" });
      const key2 = await insertTestOrgKey(provider.id, { orgId: "org-2" });

      expect(key2.id).toBeDefined();
    });

    it("should cascade delete when provider is deleted", async () => {
      const provider = await insertTestProvider({ name: "temp-provider" });
      const key = await insertTestOrgKey(provider.id);

      await db.delete(providers).where(eq(providers.id, provider.id));

      const found = await db.query.orgKeys.findFirst({
        where: eq(orgKeys.id, key.id),
      });
      expect(found).toBeUndefined();
    });
  });

  describe("platformKeys table", () => {
    it("should create a platform key linked to provider", async () => {
      const provider = await insertTestProvider({ name: "openai" });
      const key = await insertTestPlatformKey(provider.id);

      expect(key.id).toBeDefined();
      expect(key.providerId).toBe(provider.id);
    });

    it("should enforce unique provider", async () => {
      const provider = await insertTestProvider({ name: "openai" });
      await insertTestPlatformKey(provider.id);

      await expect(
        insertTestPlatformKey(provider.id)
      ).rejects.toThrow();
    });

    it("should cascade delete when provider is deleted", async () => {
      const provider = await insertTestProvider({ name: "temp-provider" });
      const key = await insertTestPlatformKey(provider.id);

      await db.delete(providers).where(eq(providers.id, provider.id));

      const found = await db.query.platformKeys.findFirst({
        where: eq(platformKeys.id, key.id),
      });
      expect(found).toBeUndefined();
    });
  });

  describe("orgProviderKeySources table", () => {
    it("should create a key source preference", async () => {
      const provider = await insertTestProvider({ name: "anthropic" });
      const pref = await insertTestOrgProviderKeySource({
        orgId: "org-1",
        providerId: provider.id,
        keySource: "org",
      });

      expect(pref.id).toBeDefined();
      expect(pref.orgId).toBe("org-1");
      expect(pref.keySource).toBe("org");
    });

    it("should enforce unique org+provider", async () => {
      const provider = await insertTestProvider({ name: "anthropic" });
      await insertTestOrgProviderKeySource({ orgId: "org-1", providerId: provider.id });

      await expect(
        insertTestOrgProviderKeySource({ orgId: "org-1", providerId: provider.id })
      ).rejects.toThrow();
    });

    it("should allow same provider for different orgs", async () => {
      const provider = await insertTestProvider({ name: "anthropic" });
      await insertTestOrgProviderKeySource({ orgId: "org-1", providerId: provider.id });
      const pref2 = await insertTestOrgProviderKeySource({ orgId: "org-2", providerId: provider.id });

      expect(pref2.id).toBeDefined();
    });

    it("should cascade delete when provider is deleted", async () => {
      const provider = await insertTestProvider({ name: "temp-provider" });
      const pref = await insertTestOrgProviderKeySource({ orgId: "org-1", providerId: provider.id });

      await db.delete(providers).where(eq(providers.id, provider.id));

      const found = await db.query.orgProviderKeySources.findFirst({
        where: eq(orgProviderKeySources.id, pref.id),
      });
      expect(found).toBeUndefined();
    });
  });

  describe("providerRequirements table", () => {
    it("should create a provider requirement", async () => {
      const req = await insertTestProviderRequirement({
        service: "apollo",
        method: "POST",
        path: "/leads/search",
        provider: "apollo",
      });

      expect(req.id).toBeDefined();
      expect(req.service).toBe("apollo");
      expect(req.method).toBe("POST");
      expect(req.path).toBe("/leads/search");
      expect(req.provider).toBe("apollo");
    });

    it("should enforce unique service+method+path+provider", async () => {
      await insertTestProviderRequirement({
        service: "apollo",
        method: "POST",
        path: "/leads/search",
        provider: "apollo",
      });

      await expect(
        insertTestProviderRequirement({
          service: "apollo",
          method: "POST",
          path: "/leads/search",
          provider: "apollo",
        })
      ).rejects.toThrow();
    });

    it("should allow same endpoint with different providers", async () => {
      await insertTestProviderRequirement({ provider: "apollo" });
      const req2 = await insertTestProviderRequirement({ provider: "firecrawl" });

      expect(req2.id).toBeDefined();
    });

    it("should allow same provider for different endpoints", async () => {
      await insertTestProviderRequirement({ path: "/leads/search" });
      const req2 = await insertTestProviderRequirement({ path: "/leads/enrich" });

      expect(req2.id).toBeDefined();
    });
  });
});
