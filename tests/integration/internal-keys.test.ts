import { describe, it, expect, beforeAll, beforeEach, afterEach, afterAll, vi } from "vitest";
import request from "supertest";
import express from "express";
import { and, eq } from "drizzle-orm";
import { serviceKeyAuth } from "../../src/middleware/auth.js";
import internalKeysRoutes from "../../src/routes/internal-keys.js";
import { db } from "../../src/db/index.js";
import { orgKeys, orgProviderKeySources, platformKeys, providers, userAuthKeys } from "../../src/db/schema.js";
import {
  cleanTestData,
  closeDb,
  insertTestOrgKey,
  insertTestOrgProviderKeySource,
  insertTestPlatformKey,
  insertTestProvider,
  insertTestUserAuthKey,
  randomId,
} from "../helpers/test-db.js";

const SERVICE_KEY = "test-service-key-123";

function createApp() {
  const app = express();
  app.use(express.json());
  app.use("/internal/keys", serviceKeyAuth, internalKeysRoutes);
  return app;
}

describe("Internal org key teardown", () => {
  let app: ReturnType<typeof createApp>;

  beforeAll(() => {
    process.env.KEY_SERVICE_API_KEY = SERVICE_KEY;
    app = createApp();
  });

  beforeEach(async () => {
    await cleanTestData();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  afterAll(async () => {
    await cleanTestData();
    await closeDb();
  });

  it("deletes all key-service-owned credential material for the org only", async () => {
    const orgId = randomId();
    const otherOrgId = randomId();
    const providerA = await insertTestProvider({ name: `anthropic-${randomId()}` });
    const providerB = await insertTestProvider({ name: `openai-${randomId()}` });

    await insertTestOrgKey(providerA.id, { orgId });
    await insertTestOrgKey(providerB.id, { orgId });
    await insertTestOrgProviderKeySource({ orgId, providerId: providerA.id, keySource: "org" });
    await insertTestOrgProviderKeySource({ orgId, providerId: providerB.id, keySource: "platform" });
    await insertTestUserAuthKey({ orgId, userId: randomId(), createdBy: randomId() });

    await insertTestOrgKey(providerA.id, { orgId: otherOrgId });
    await insertTestOrgProviderKeySource({ orgId: otherOrgId, providerId: providerA.id, keySource: "org" });
    await insertTestUserAuthKey({ orgId: otherOrgId, userId: randomId(), createdBy: randomId() });
    await insertTestPlatformKey(providerA.id);

    const res = await request(app)
      .delete(`/internal/keys/by-org/${orgId}`)
      .set("x-api-key", SERVICE_KEY);

    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({
      orgId,
      deleted: {
        orgKeys: 2,
        keySources: 2,
        apiKeys: 1,
      },
    });

    const remainingOrgKeys = await db.query.orgKeys.findMany({
      where: eq(orgKeys.orgId, orgId),
    });
    const remainingKeySources = await db.query.orgProviderKeySources.findMany({
      where: eq(orgProviderKeySources.orgId, orgId),
    });
    const remainingApiKeys = await db.query.userAuthKeys.findMany({
      where: eq(userAuthKeys.orgId, orgId),
    });

    expect(remainingOrgKeys).toHaveLength(0);
    expect(remainingKeySources).toHaveLength(0);
    expect(remainingApiKeys).toHaveLength(0);

    await expect(
      db.query.orgKeys.findFirst({
        where: and(eq(orgKeys.orgId, otherOrgId), eq(orgKeys.providerId, providerA.id)),
      })
    ).resolves.toBeDefined();
    await expect(
      db.query.orgProviderKeySources.findFirst({
        where: and(
          eq(orgProviderKeySources.orgId, otherOrgId),
          eq(orgProviderKeySources.providerId, providerA.id)
        ),
      })
    ).resolves.toBeDefined();
    await expect(
      db.query.userAuthKeys.findFirst({
        where: eq(userAuthKeys.orgId, otherOrgId),
      })
    ).resolves.toBeDefined();
    await expect(
      db.query.platformKeys.findFirst({
        where: eq(platformKeys.providerId, providerA.id),
      })
    ).resolves.toBeDefined();
    await expect(
      db.query.providers.findFirst({
        where: eq(providers.id, providerA.id),
      })
    ).resolves.toBeDefined();
  });

  it("succeeds when the org has no credential records", async () => {
    const orgId = randomId();

    const res = await request(app)
      .delete(`/internal/keys/by-org/${orgId}`)
      .set("x-api-key", SERVICE_KEY);

    expect(res.status).toBe(200);
    expect(res.body.deleted).toEqual({
      orgKeys: 0,
      keySources: 0,
      apiKeys: 0,
    });
  });

  it("is safe to retry after deleting an org", async () => {
    const orgId = randomId();
    const provider = await insertTestProvider({ name: `retry-${randomId()}` });

    await insertTestOrgKey(provider.id, { orgId });
    await insertTestOrgProviderKeySource({ orgId, providerId: provider.id, keySource: "org" });
    await insertTestUserAuthKey({ orgId, userId: randomId(), createdBy: randomId() });

    const first = await request(app)
      .delete(`/internal/keys/by-org/${orgId}`)
      .set("x-api-key", SERVICE_KEY);
    const second = await request(app)
      .delete(`/internal/keys/by-org/${orgId}`)
      .set("x-api-key", SERVICE_KEY);

    expect(first.status).toBe(200);
    expect(second.status).toBe(200);
    expect(second.body.deleted).toEqual({
      orgKeys: 0,
      keySources: 0,
      apiKeys: 0,
    });
  });

  it("rejects requests without valid service auth", async () => {
    const res = await request(app)
      .delete(`/internal/keys/by-org/${randomId()}`)
      .set("x-api-key", "wrong-key");

    expect(res.status).toBe(401);
  });

  it("rejects non-UUID org identifiers", async () => {
    const res = await request(app)
      .delete("/internal/keys/by-org/org_external_clerk_id")
      .set("x-api-key", SERVICE_KEY);

    expect(res.status).toBe(400);
    expect(res.body.error).toContain("internal org UUID");
  });

  it("returns non-2xx when the database operation fails", async () => {
    vi.spyOn(db, "transaction").mockRejectedValueOnce(new Error("database unavailable"));

    const res = await request(app)
      .delete(`/internal/keys/by-org/${randomId()}`)
      .set("x-api-key", SERVICE_KEY);

    expect(res.status).toBe(500);
    expect(res.body.error).toBe("Internal server error");
  });
});
