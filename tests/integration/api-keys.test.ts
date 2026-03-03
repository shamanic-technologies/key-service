import { describe, it, expect, beforeAll, beforeEach, afterAll } from "vitest";
import request from "supertest";
import express from "express";
import { serviceKeyAuth, requireIdentityHeaders } from "../../src/middleware/auth.js";
import apiKeysRoutes from "../../src/routes/api-keys.js";
import validateRoutes from "../../src/routes/validate.js";
import { cleanTestData, closeDb, randomId } from "../helpers/test-db.js";

const SERVICE_KEY = "test-service-key-123";

function createApp() {
  const app = express();
  app.use(express.json());
  // /validate is exempt from identity headers (discovers identity from key)
  app.use(serviceKeyAuth, validateRoutes);
  app.use("/api-keys", serviceKeyAuth, requireIdentityHeaders, apiKeysRoutes);
  return app;
}

describe("User API Keys", () => {
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

  describe("POST /api-keys", () => {
    it("should create a user API key with orgId from identity header", async () => {
      const userId = randomId();
      const createdBy = randomId();

      const res = await request(app)
        .post("/api-keys")
        .set("x-api-key", SERVICE_KEY)
        .set({ "x-org-id": "org-uuid-123", "x-user-id": "caller-user" })
        .send({
          userId,
          createdBy,
          name: "Polarity Course — Kevin",
        });

      expect(res.status).toBe(200);
      expect(res.body.key).toMatch(/^distrib\.usr_/);
      expect(res.body.name).toBe("Polarity Course — Kevin");
      expect(res.body.orgId).toBe("org-uuid-123");
      expect(res.body.userId).toBe(userId);
      expect(res.body.createdBy).toBe(createdBy);
      expect(res.body.createdAt).toBeDefined();
      expect(res.body.id).toBeDefined();
    });

    it("should reject request missing required fields", async () => {
      const res = await request(app)
        .post("/api-keys")
        .set("x-api-key", SERVICE_KEY)
        .set({ "x-org-id": "org-uuid-123", "x-user-id": "caller-user" })
        .send({});

      expect(res.status).toBe(400);
    });

    it("should allow different createdBy than userId (admin creates for member)", async () => {
      const userId = randomId();
      const adminId = randomId();

      const res = await request(app)
        .post("/api-keys")
        .set("x-api-key", SERVICE_KEY)
        .set({ "x-org-id": "org-uuid-admin", "x-user-id": "caller-user" })
        .send({
          userId,
          createdBy: adminId,
          name: "Created by admin",
        });

      expect(res.status).toBe(200);
      expect(res.body.userId).toBe(userId);
      expect(res.body.createdBy).toBe(adminId);
    });

    it("should reject request without identity headers", async () => {
      const res = await request(app)
        .post("/api-keys")
        .set("x-api-key", SERVICE_KEY)
        .send({
          userId: randomId(),
          createdBy: randomId(),
          name: "Test",
        });

      expect(res.status).toBe(400);
      expect(res.body.error).toContain("x-org-id");
    });
  });

  describe("GET /api-keys", () => {
    it("should list keys for an org", async () => {
      const userId = randomId();
      const orgId = "org-list-test";

      await request(app)
        .post("/api-keys")
        .set("x-api-key", SERVICE_KEY)
        .set({ "x-org-id": orgId, "x-user-id": "caller-user" })
        .send({
          userId,
          createdBy: userId,
          name: "List Test Key",
        });

      const res = await request(app)
        .get("/api-keys")
        .set("x-api-key", SERVICE_KEY)
        .set({ "x-org-id": orgId, "x-user-id": "caller-user" });

      expect(res.status).toBe(200);
      expect(res.body.keys).toHaveLength(1);
      expect(res.body.keys[0].orgId).toBe(orgId);
      expect(res.body.keys[0].userId).toBe(userId);
      expect(res.body.keys[0].createdBy).toBe(userId);
      expect(res.body.keys[0].keyPrefix).toMatch(/^distrib\.usr_/);
    });

    it("should filter by userId", async () => {
      const user1 = randomId();
      const user2 = randomId();
      const orgId = "org-filter-test";

      await request(app)
        .post("/api-keys")
        .set("x-api-key", SERVICE_KEY)
        .set({ "x-org-id": orgId, "x-user-id": "caller-user" })
        .send({
          userId: user1,
          createdBy: user1,
          name: "User 1 Key",
        });

      await request(app)
        .post("/api-keys")
        .set("x-api-key", SERVICE_KEY)
        .set({ "x-org-id": orgId, "x-user-id": "caller-user" })
        .send({
          userId: user2,
          createdBy: user2,
          name: "User 2 Key",
        });

      const allRes = await request(app)
        .get("/api-keys")
        .set("x-api-key", SERVICE_KEY)
        .set({ "x-org-id": orgId, "x-user-id": "caller-user" });

      expect(allRes.body.keys).toHaveLength(2);

      const filteredRes = await request(app)
        .get("/api-keys")
        .set("x-api-key", SERVICE_KEY)
        .set({ "x-org-id": orgId, "x-user-id": "caller-user" })
        .query({ userId: user1 });

      expect(filteredRes.body.keys).toHaveLength(1);
      expect(filteredRes.body.keys[0].userId).toBe(user1);
    });
  });

  describe("DELETE /api-keys/:id", () => {
    it("should delete a key", async () => {
      const userId = randomId();
      const orgId = "org-delete-test";

      const create = await request(app)
        .post("/api-keys")
        .set("x-api-key", SERVICE_KEY)
        .set({ "x-org-id": orgId, "x-user-id": "caller-user" })
        .send({
          userId,
          createdBy: userId,
          name: "Delete Me",
        });

      const res = await request(app)
        .delete(`/api-keys/${create.body.id}`)
        .set("x-api-key", SERVICE_KEY)
        .set({ "x-org-id": orgId, "x-user-id": "caller-user" });

      expect(res.status).toBe(200);

      const list = await request(app)
        .get("/api-keys")
        .set("x-api-key", SERVICE_KEY)
        .set({ "x-org-id": orgId, "x-user-id": "caller-user" });

      expect(list.body.keys).toHaveLength(0);
    });
  });

  describe("GET /validate with user key", () => {
    it("should return orgId, userId for user keys", async () => {
      const userId = randomId();
      const orgId = "org-validate-test";

      const create = await request(app)
        .post("/api-keys")
        .set("x-api-key", SERVICE_KEY)
        .set({ "x-org-id": orgId, "x-user-id": "caller-user" })
        .send({
          userId,
          createdBy: userId,
          name: "Validate Test",
        });

      const userKey = create.body.key;

      const res = await request(app)
        .get("/validate")
        .set("x-api-key", SERVICE_KEY)
        .query({ key: userKey });

      expect(res.status).toBe(200);
      expect(res.body.valid).toBe(true);
      expect(res.body.type).toBe("user");
      expect(res.body.orgId).toBe(orgId);
      expect(res.body.userId).toBe(userId);
      expect(res.body.configuredProviders).toBeDefined();
    });

    it("should reject invalid user key", async () => {
      const res = await request(app)
        .get("/validate")
        .set("x-api-key", SERVICE_KEY)
        .query({ key: "distrib.usr_0000000000000000000000000000000000000000" });

      expect(res.status).toBe(401);
    });

    it("should reject keys with unrecognized prefix", async () => {
      const res = await request(app)
        .get("/validate")
        .set("x-api-key", SERVICE_KEY)
        .query({ key: "unknown_0000000000000000000000000000000000000000" });

      expect(res.status).toBe(401);
    });

    it("should reject request without key parameter", async () => {
      const res = await request(app)
        .get("/validate")
        .set("x-api-key", SERVICE_KEY);

      expect(res.status).toBe(400);
      expect(res.body.error).toContain("key");
    });

    it("should reject request without service key auth", async () => {
      const res = await request(app)
        .get("/validate")
        .query({ key: "distrib.usr_0000000000000000000000000000000000000000" });

      expect(res.status).toBe(401);
      expect(res.body.error).toBe("Invalid service key");
    });

    it("should work without identity headers (validate is exempt)", async () => {
      const userId = randomId();
      const orgId = "org-validate-no-headers";

      const create = await request(app)
        .post("/api-keys")
        .set("x-api-key", SERVICE_KEY)
        .set({ "x-org-id": orgId, "x-user-id": "caller-user" })
        .send({
          userId,
          createdBy: userId,
          name: "No Headers Test",
        });

      // /validate should work without x-org-id / x-user-id
      const res = await request(app)
        .get("/validate")
        .set("x-api-key", SERVICE_KEY)
        .query({ key: create.body.key });

      expect(res.status).toBe(200);
      expect(res.body.valid).toBe(true);
    });
  });

  describe("POST /api-keys/session", () => {
    it("should create a session key using identity headers", async () => {
      const userId = randomId();
      const orgId = "org-session-test";

      const res = await request(app)
        .post("/api-keys/session")
        .set("x-api-key", SERVICE_KEY)
        .set({ "x-org-id": orgId, "x-user-id": userId });

      expect(res.status).toBe(200);
      expect(res.body.key).toMatch(/^distrib\.usr_/);
      expect(res.body.name).toBe("Default");
    });

    it("should return same session key on subsequent calls", async () => {
      const userId = randomId();
      const orgId = "org-session-idempotent";

      const first = await request(app)
        .post("/api-keys/session")
        .set("x-api-key", SERVICE_KEY)
        .set({ "x-org-id": orgId, "x-user-id": userId });

      const second = await request(app)
        .post("/api-keys/session")
        .set("x-api-key", SERVICE_KEY)
        .set({ "x-org-id": orgId, "x-user-id": userId });

      expect(first.body.key).toBe(second.body.key);
      expect(first.body.id).toBe(second.body.id);
    });

    it("should create different session keys for different users in same org", async () => {
      const user1 = randomId();
      const user2 = randomId();
      const orgId = "org-multi-user";

      const res1 = await request(app)
        .post("/api-keys/session")
        .set("x-api-key", SERVICE_KEY)
        .set({ "x-org-id": orgId, "x-user-id": user1 });

      const res2 = await request(app)
        .post("/api-keys/session")
        .set("x-api-key", SERVICE_KEY)
        .set({ "x-org-id": orgId, "x-user-id": user2 });

      expect(res1.body.key).not.toBe(res2.body.key);
    });
  });
});
