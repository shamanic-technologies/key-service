import { describe, it, expect, beforeAll, beforeEach, afterAll } from "vitest";
import request from "supertest";
import express from "express";
import { eq } from "drizzle-orm";
import { serviceKeyAuth } from "../../src/middleware/auth.js";
import userApiKeysRoutes from "../../src/routes/user-api-keys.js";
import { db } from "../../src/db/index.js";
import { userAuthKeys } from "../../src/db/schema.js";
import { cleanTestData, closeDb, insertTestUserAuthKey, randomId } from "../helpers/test-db.js";

const SERVICE_KEY = "test-service-key-123";

function createApp() {
  const app = express();
  app.use(express.json());
  app.use("/internal/user-api-keys", serviceKeyAuth, userApiKeysRoutes);
  return app;
}

describe("A user's own API keys across orgs (/internal/user-api-keys)", () => {
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

  it("requires the service key", async () => {
    const res = await request(app).get(`/internal/user-api-keys/by-user/${randomId()}`);
    expect(res.status).toBe(401);
  });

  it("lists every key the user owns, in every org, and no one else's", async () => {
    const kevin = randomId();
    const colleague = randomId();
    const orgA = randomId();
    const orgB = randomId();
    const k1 = await insertTestUserAuthKey({ userId: kevin, orgId: orgA, name: "A" });
    const k2 = await insertTestUserAuthKey({ userId: kevin, orgId: orgB, name: "B" });
    await insertTestUserAuthKey({ userId: colleague, orgId: orgA, name: "colleague in A" });

    const res = await request(app)
      .get(`/internal/user-api-keys/by-user/${kevin}`)
      .set("x-api-key", SERVICE_KEY);

    expect(res.status).toBe(200);
    const ids = res.body.keys.map((k: { id: string }) => k.id).sort();
    expect(ids).toEqual([k1.id, k2.id].sort());
    expect(new Set(res.body.keys.map((k: { orgId: string }) => k.orgId))).toEqual(new Set([orgA, orgB]));
    for (const k of res.body.keys) {
      expect(k.userId).toBe(kevin);
      expect(k).not.toHaveProperty("encryptedKey");
      expect(k).not.toHaveProperty("keyHash");
    }

    const theirs = await request(app)
      .get(`/internal/user-api-keys/by-user/${colleague}`)
      .set("x-api-key", SERVICE_KEY);
    expect(theirs.body.keys.map((k: { name: string }) => k.name)).toEqual(["colleague in A"]);
  });

  it("does not need x-org-id", async () => {
    const kevin = randomId();
    await insertTestUserAuthKey({ userId: kevin, orgId: randomId() });
    const res = await request(app)
      .get(`/internal/user-api-keys/by-user/${kevin}`)
      .set("x-api-key", SERVICE_KEY);
    expect(res.status).toBe(200);
    expect(res.body.keys).toHaveLength(1);
  });

  it("returns an empty list for a user with no keys", async () => {
    const res = await request(app)
      .get(`/internal/user-api-keys/by-user/${randomId()}`)
      .set("x-api-key", SERVICE_KEY);
    expect(res.status).toBe(200);
    expect(res.body.keys).toEqual([]);
  });

  it("rejects a non-UUID userId instead of matching nothing", async () => {
    const res = await request(app)
      .get(`/internal/user-api-keys/by-user/not-a-uuid`)
      .set("x-api-key", SERVICE_KEY);
    expect(res.status).toBe(400);
  });

  it("lets the owner revoke a key minted in any org", async () => {
    const kevin = randomId();
    const otherOrg = randomId();
    const key = await insertTestUserAuthKey({ userId: kevin, orgId: otherOrg });

    const res = await request(app)
      .delete(`/internal/user-api-keys/by-user/${kevin}/${key.id}`)
      .set("x-api-key", SERVICE_KEY);

    expect(res.status).toBe(200);
    expect(res.body.id).toBe(key.id);
    expect(res.body.orgId).toBe(otherOrg);
    const left = await db.select().from(userAuthKeys).where(eq(userAuthKeys.id, key.id));
    expect(left).toHaveLength(0);
  });

  it("refuses to revoke another user's key (404) and leaves it in place", async () => {
    const owner = randomId();
    const intruder = randomId();
    const org = randomId();
    const key = await insertTestUserAuthKey({ userId: owner, orgId: org });

    const res = await request(app)
      .delete(`/internal/user-api-keys/by-user/${intruder}/${key.id}`)
      .set("x-api-key", SERVICE_KEY);

    expect(res.status).toBe(404);
    const left = await db.select().from(userAuthKeys).where(eq(userAuthKeys.id, key.id));
    expect(left).toHaveLength(1);
  });

  it("answers 404 for an unknown or malformed key id", async () => {
    const kevin = randomId();
    const unknown = await request(app)
      .delete(`/internal/user-api-keys/by-user/${kevin}/${randomId()}`)
      .set("x-api-key", SERVICE_KEY);
    expect(unknown.status).toBe(404);
    const malformed = await request(app)
      .delete(`/internal/user-api-keys/by-user/${kevin}/nope`)
      .set("x-api-key", SERVICE_KEY);
    expect(malformed.status).toBe(404);
  });
});
