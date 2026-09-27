import { describe, it, expect, beforeAll, beforeEach, afterAll } from "vitest";
import request from "supertest";
import express from "express";
import { and, eq } from "drizzle-orm";
import { serviceKeyAuth, requireIdentityHeaders } from "../../src/middleware/auth.js";
import transferBrandRoutes from "../../src/routes/transfer-brand.js";
import brandKeysRoutes from "../../src/routes/brand-keys.js";
import { db } from "../../src/db/index.js";
import { brandKeys, orgKeys } from "../../src/db/schema.js";
import { encrypt } from "../../src/lib/crypto.js";
import {
  cleanTestData,
  closeDb,
  insertTestBrandKey,
  insertTestOrgKey,
  insertTestProvider,
  randomId,
} from "../helpers/test-db.js";

const SERVICE_KEY = "test-service-key-123";

function createApp() {
  const app = express();
  app.use(express.json());
  app.use("/keys/brands", serviceKeyAuth, requireIdentityHeaders, brandKeysRoutes);
  app.use("/internal/transfer-brand", serviceKeyAuth, transferBrandRoutes);
  return app;
}

describe("POST /internal/transfer-brand", () => {
  let app: ReturnType<typeof createApp>;

  beforeAll(() => {
    process.env.KEY_SERVICE_API_KEY = SERVICE_KEY;
    app = createApp();
  });

  beforeEach(async () => {
    await cleanTestData();
  });

  afterAll(async () => {
    await cleanTestData();
    await closeDb();
  });

  function transfer(body: Record<string, unknown>) {
    return request(app).post("/internal/transfer-brand").set("x-api-key", SERVICE_KEY).send(body);
  }

  function decrypt(orgId: string, brandId: string, provider: string) {
    return request(app)
      .get(`/keys/brands/${brandId}/${provider}/decrypt`)
      .set("x-api-key", SERVICE_KEY)
      .set("x-org-id", orgId)
      .set("x-user-id", randomId())
      .set("x-caller-service", "test")
      .set("x-caller-method", "GET")
      .set("x-caller-path", "/test");
  }

  it("moves the brand's credentials so they resolve under the target org and not the source", async () => {
    const sourceOrgId = randomId();
    const targetOrgId = randomId();
    const brandId = randomId();
    const otherBrandId = randomId();
    const provider = await insertTestProvider({ name: `instantly-${randomId()}` });

    await insertTestBrandKey(provider.id, { orgId: sourceOrgId, brandId, encryptedKey: encrypt("sk-brand-secret") });
    await insertTestBrandKey(provider.id, { orgId: sourceOrgId, brandId: otherBrandId, encryptedKey: encrypt("sk-other") });
    await insertTestOrgKey(provider.id, { orgId: sourceOrgId });

    const res = await transfer({ sourceBrandId: brandId, sourceOrgId, targetOrgId });
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ updatedTables: [{ tableName: "brand_keys", count: 1 }] });
    expect(JSON.stringify(res.body)).not.toContain("sk-brand-secret");

    const underTarget = await decrypt(targetOrgId, brandId, provider.name);
    expect(underTarget.status).toBe(200);
    expect(underTarget.body.key).toBe("sk-brand-secret");

    const underSource = await decrypt(sourceOrgId, brandId, provider.name);
    expect(underSource.status).toBe(404);

    // Another brand of the source org and the org-wide key stay where they were.
    expect((await decrypt(sourceOrgId, otherBrandId, provider.name)).status).toBe(200);
    const orgRows = await db.select().from(orgKeys).where(eq(orgKeys.orgId, sourceOrgId));
    expect(orgRows).toHaveLength(1);
  });

  it("rewrites the brand id to targetBrandId when given", async () => {
    const sourceOrgId = randomId();
    const targetOrgId = randomId();
    const brandId = randomId();
    const newBrandId = randomId();
    const provider = await insertTestProvider({ name: `apollo-${randomId()}` });
    await insertTestBrandKey(provider.id, { orgId: sourceOrgId, brandId, encryptedKey: encrypt("sk-1") });

    const res = await transfer({ sourceBrandId: brandId, sourceOrgId, targetOrgId, targetBrandId: newBrandId });
    expect(res.status).toBe(200);
    expect(res.body.updatedTables[0].count).toBe(1);

    expect((await decrypt(targetOrgId, newBrandId, provider.name)).body.key).toBe("sk-1");
    expect((await decrypt(targetOrgId, brandId, provider.name)).status).toBe(404);
    expect((await decrypt(sourceOrgId, brandId, provider.name)).status).toBe(404);
  });

  it("is idempotent: a second call moves nothing and leaves the key resolvable", async () => {
    const sourceOrgId = randomId();
    const targetOrgId = randomId();
    const brandId = randomId();
    const provider = await insertTestProvider({ name: `postmark-${randomId()}` });
    await insertTestBrandKey(provider.id, { orgId: sourceOrgId, brandId, encryptedKey: encrypt("sk-2") });

    const body = { sourceBrandId: brandId, sourceOrgId, targetOrgId };
    expect((await transfer(body)).body.updatedTables[0].count).toBe(1);
    const second = await transfer(body);
    expect(second.status).toBe(200);
    expect(second.body.updatedTables[0].count).toBe(0);
    expect((await decrypt(targetOrgId, brandId, provider.name)).body.key).toBe("sk-2");
  });

  it("keeps the target's own credential on collision and still empties the source", async () => {
    const sourceOrgId = randomId();
    const targetOrgId = randomId();
    const brandId = randomId();
    const provider = await insertTestProvider({ name: `stripe-${randomId()}` });
    await insertTestBrandKey(provider.id, { orgId: sourceOrgId, brandId, encryptedKey: encrypt("sk-old") });
    await insertTestBrandKey(provider.id, { orgId: targetOrgId, brandId, encryptedKey: encrypt("sk-new") });

    const res = await transfer({ sourceBrandId: brandId, sourceOrgId, targetOrgId });
    expect(res.status).toBe(200);
    expect(res.body.updatedTables[0].count).toBe(1);

    expect((await decrypt(targetOrgId, brandId, provider.name)).body.key).toBe("sk-new");
    const left = await db
      .select()
      .from(brandKeys)
      .where(and(eq(brandKeys.orgId, sourceOrgId), eq(brandKeys.brandId, brandId)));
    expect(left).toHaveLength(0);
  });

  it("finishes a prior move made without targetBrandId when called again with it", async () => {
    const sourceOrgId = randomId();
    const targetOrgId = randomId();
    const brandId = randomId();
    const newBrandId = randomId();
    const provider = await insertTestProvider({ name: `anthropic-${randomId()}` });
    await insertTestBrandKey(provider.id, { orgId: sourceOrgId, brandId, encryptedKey: encrypt("sk-3") });

    await transfer({ sourceBrandId: brandId, sourceOrgId, targetOrgId });
    const res = await transfer({ sourceBrandId: brandId, sourceOrgId, targetOrgId, targetBrandId: newBrandId });
    expect(res.body.updatedTables[0].count).toBe(1);
    expect((await decrypt(targetOrgId, newBrandId, provider.name)).body.key).toBe("sk-3");
  });

  it("rejects a malformed body", async () => {
    const res = await transfer({ sourceBrandId: "not-a-uuid", sourceOrgId: randomId() });
    expect(res.status).toBe(400);
  });

  it("requires the service key", async () => {
    const res = await request(app)
      .post("/internal/transfer-brand")
      .send({ sourceBrandId: randomId(), sourceOrgId: randomId(), targetOrgId: randomId() });
    expect(res.status).toBe(401);
  });
});
