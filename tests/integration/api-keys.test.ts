import { describe, it, expect, beforeAll, beforeEach, afterAll } from "vitest";
import request from "supertest";
import express from "express";
import { serviceKeyAuth } from "../../src/middleware/auth.js";
import internalRoutes from "../../src/routes/internal.js";
import validateRoutes from "../../src/routes/validate.js";
import { cleanTestData, closeDb, randomId } from "../helpers/test-db.js";

const SERVICE_KEY = "test-service-key-123";

function createApp() {
  const app = express();
  app.use(express.json());
  app.use(validateRoutes);
  app.use("/internal", serviceKeyAuth, internalRoutes);
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

  describe("POST /internal/api-keys", () => {
    it("should create a user API key with appId, orgId, userId, createdBy", async () => {
      const userId = randomId();
      const createdBy = randomId();

      const res = await request(app)
        .post("/internal/api-keys")
        .set("x-api-key", SERVICE_KEY)
        .send({
          appId: "distribute-frontend",
          orgId: "org-uuid-123",
          userId,
          createdBy,
          name: "Polarity Course — Kevin",
        });

      expect(res.status).toBe(200);
      expect(res.body.key).toMatch(/^distrib\.usr_/);
      expect(res.body.name).toBe("Polarity Course — Kevin");
      expect(res.body.appId).toBe("distribute-frontend");
      expect(res.body.orgId).toBe("org-uuid-123");
      expect(res.body.userId).toBe(userId);
      expect(res.body.createdBy).toBe(createdBy);
      expect(res.body.createdAt).toBeDefined();
      expect(res.body.id).toBeDefined();
    });

    it("should reject request missing required fields", async () => {
      const res = await request(app)
        .post("/internal/api-keys")
        .set("x-api-key", SERVICE_KEY)
        .send({ orgId: "org-uuid-123" });

      expect(res.status).toBe(400);
    });

    it("should reject request with invalid userId format", async () => {
      const res = await request(app)
        .post("/internal/api-keys")
        .set("x-api-key", SERVICE_KEY)
        .send({
          appId: "test-app",
          orgId: "org-uuid",
          userId: "not-a-uuid",
          createdBy: randomId(),
          name: "Test",
        });

      expect(res.status).toBe(400);
    });

    it("should allow different createdBy than userId (admin creates for member)", async () => {
      const userId = randomId();
      const adminId = randomId();

      const res = await request(app)
        .post("/internal/api-keys")
        .set("x-api-key", SERVICE_KEY)
        .send({
          appId: "test-app",
          orgId: "org-uuid-admin",
          userId,
          createdBy: adminId,
          name: "Created by admin",
        });

      expect(res.status).toBe(200);
      expect(res.body.userId).toBe(userId);
      expect(res.body.createdBy).toBe(adminId);
    });
  });

  describe("GET /internal/api-keys", () => {
    it("should list keys for an org with new fields", async () => {
      const userId = randomId();

      await request(app)
        .post("/internal/api-keys")
        .set("x-api-key", SERVICE_KEY)
        .send({
          appId: "test-app",
          orgId: "org-list-test",
          userId,
          createdBy: userId,
          name: "List Test Key",
        });

      const res = await request(app)
        .get("/internal/api-keys")
        .set("x-api-key", SERVICE_KEY)
        .query({ orgId: "org-list-test" });

      expect(res.status).toBe(200);
      expect(res.body.keys).toHaveLength(1);
      expect(res.body.keys[0].appId).toBe("test-app");
      expect(res.body.keys[0].orgId).toBe("org-list-test");
      expect(res.body.keys[0].userId).toBe(userId);
      expect(res.body.keys[0].createdBy).toBe(userId);
      expect(res.body.keys[0].keyPrefix).toMatch(/^distrib\.usr_/);
    });

    it("should filter by userId", async () => {
      const user1 = randomId();
      const user2 = randomId();

      // Create keys for two different users in same org
      await request(app)
        .post("/internal/api-keys")
        .set("x-api-key", SERVICE_KEY)
        .send({
          appId: "test-app",
          orgId: "org-filter-test",
          userId: user1,
          createdBy: user1,
          name: "User 1 Key",
        });

      await request(app)
        .post("/internal/api-keys")
        .set("x-api-key", SERVICE_KEY)
        .send({
          appId: "test-app",
          orgId: "org-filter-test",
          userId: user2,
          createdBy: user2,
          name: "User 2 Key",
        });

      // List all — should have 2
      const allRes = await request(app)
        .get("/internal/api-keys")
        .set("x-api-key", SERVICE_KEY)
        .query({ orgId: "org-filter-test" });

      expect(allRes.body.keys).toHaveLength(2);

      // Filter by user1 — should have 1
      const filteredRes = await request(app)
        .get("/internal/api-keys")
        .set("x-api-key", SERVICE_KEY)
        .query({ orgId: "org-filter-test", userId: user1 });

      expect(filteredRes.body.keys).toHaveLength(1);
      expect(filteredRes.body.keys[0].userId).toBe(user1);
    });
  });

  describe("DELETE /internal/api-keys/:id", () => {
    it("should delete a key", async () => {
      const userId = randomId();

      const create = await request(app)
        .post("/internal/api-keys")
        .set("x-api-key", SERVICE_KEY)
        .send({
          appId: "test-app",
          orgId: "org-delete-test",
          userId,
          createdBy: userId,
          name: "Delete Me",
        });

      const res = await request(app)
        .delete(`/internal/api-keys/${create.body.id}`)
        .set("x-api-key", SERVICE_KEY)
        .send({ orgId: "org-delete-test" });

      expect(res.status).toBe(200);

      // Verify deleted
      const list = await request(app)
        .get("/internal/api-keys")
        .set("x-api-key", SERVICE_KEY)
        .query({ orgId: "org-delete-test" });

      expect(list.body.keys).toHaveLength(0);
    });
  });

  describe("GET /validate with user key", () => {
    it("should return appId, orgId, userId for user keys", async () => {
      const userId = randomId();

      const create = await request(app)
        .post("/internal/api-keys")
        .set("x-api-key", SERVICE_KEY)
        .send({
          appId: "distribute-frontend",
          orgId: "org-validate-test",
          userId,
          createdBy: userId,
          name: "Validate Test",
        });

      const userKey = create.body.key;

      const res = await request(app)
        .get("/validate")
        .set("Authorization", `Bearer ${userKey}`);

      expect(res.status).toBe(200);
      expect(res.body.valid).toBe(true);
      expect(res.body.type).toBe("user");
      expect(res.body.appId).toBe("distribute-frontend");
      expect(res.body.orgId).toBe("org-validate-test");
      expect(res.body.userId).toBe(userId);
      expect(res.body.configuredProviders).toBeDefined();
    });

    it("should reject invalid user key", async () => {
      const res = await request(app)
        .get("/validate")
        .set("Authorization", "Bearer distrib.usr_0000000000000000000000000000000000000000");

      expect(res.status).toBe(401);
    });

    it("should reject keys with unrecognized prefix", async () => {
      const res = await request(app)
        .get("/validate")
        .set("Authorization", "Bearer unknown_0000000000000000000000000000000000000000");

      expect(res.status).toBe(401);
    });
  });

  describe("POST /internal/api-keys/session", () => {
    it("should create a session key with appId, orgId, userId", async () => {
      const userId = randomId();

      const res = await request(app)
        .post("/internal/api-keys/session")
        .set("x-api-key", SERVICE_KEY)
        .send({
          appId: "test-app",
          orgId: "org-session-test",
          userId,
        });

      expect(res.status).toBe(200);
      expect(res.body.key).toMatch(/^distrib\.usr_/);
      expect(res.body.name).toBe("Default");
    });

    it("should return same session key on subsequent calls", async () => {
      const userId = randomId();
      const body = {
        appId: "test-app",
        orgId: "org-session-idempotent",
        userId,
      };

      const first = await request(app)
        .post("/internal/api-keys/session")
        .set("x-api-key", SERVICE_KEY)
        .send(body);

      const second = await request(app)
        .post("/internal/api-keys/session")
        .set("x-api-key", SERVICE_KEY)
        .send(body);

      expect(first.body.key).toBe(second.body.key);
      expect(first.body.id).toBe(second.body.id);
    });

    it("should create different session keys for different users in same org", async () => {
      const user1 = randomId();
      const user2 = randomId();

      const res1 = await request(app)
        .post("/internal/api-keys/session")
        .set("x-api-key", SERVICE_KEY)
        .send({ appId: "test-app", orgId: "org-multi-user", userId: user1 });

      const res2 = await request(app)
        .post("/internal/api-keys/session")
        .set("x-api-key", SERVICE_KEY)
        .send({ appId: "test-app", orgId: "org-multi-user", userId: user2 });

      expect(res1.body.key).not.toBe(res2.body.key);
    });
  });
});
