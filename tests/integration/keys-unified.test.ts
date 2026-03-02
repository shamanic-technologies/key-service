import { describe, it, expect, beforeEach, afterAll } from "vitest";
import request from "supertest";
import express from "express";
import keysRoutes from "../../src/routes/keys.js";
import { cleanTestData, closeDb } from "../helpers/test-db.js";

const app = express();
app.use(express.json());
app.use("/keys", keysRoutes);

const callerHeaders = {
  "x-caller-service": "test-service",
  "x-caller-method": "POST",
  "x-caller-path": "/test/endpoint",
};

describe("Unified /keys endpoints", () => {
  beforeEach(async () => {
    await cleanTestData();
  });

  afterAll(async () => {
    await cleanTestData();
    await closeDb();
  });

  // ==================== ORG KEYS ====================

  describe("keySource=org", () => {
    it("POST /keys — should create an org key", async () => {
      const res = await request(app)
        .post("/keys")
        .send({ keySource: "org", orgId: "org-1", provider: "anthropic", apiKey: "sk-ant-abc123" });

      expect(res.status).toBe(200);
      expect(res.body.provider).toBe("anthropic");
      expect(res.body.maskedKey).toBeDefined();
      expect(res.body.message).toContain("anthropic");
    });

    it("POST /keys — should upsert existing org key", async () => {
      await request(app)
        .post("/keys")
        .send({ keySource: "org", orgId: "org-1", provider: "anthropic", apiKey: "sk-old" });

      await request(app)
        .post("/keys")
        .send({ keySource: "org", orgId: "org-1", provider: "anthropic", apiKey: "sk-new" });

      const listRes = await request(app)
        .get("/keys")
        .query({ keySource: "org", orgId: "org-1" });

      expect(listRes.body.keys).toHaveLength(1);
    });

    it("POST /keys — should reject missing orgId for org source", async () => {
      const res = await request(app)
        .post("/keys")
        .send({ keySource: "org", provider: "anthropic", apiKey: "sk-abc" });

      expect(res.status).toBe(400);
    });

    it("GET /keys — should list org keys", async () => {
      await request(app)
        .post("/keys")
        .send({ keySource: "org", orgId: "org-1", provider: "anthropic", apiKey: "sk-ant-abc" });
      await request(app)
        .post("/keys")
        .send({ keySource: "org", orgId: "org-1", provider: "firecrawl", apiKey: "fc-abc" });

      const res = await request(app)
        .get("/keys")
        .query({ keySource: "org", orgId: "org-1" });

      expect(res.status).toBe(200);
      expect(res.body.keys).toHaveLength(2);
    });

    it("GET /keys — should reject missing orgId", async () => {
      const res = await request(app)
        .get("/keys")
        .query({ keySource: "org" });

      expect(res.status).toBe(400);
    });

    it("GET /keys/:provider/decrypt — should return decrypted org key", async () => {
      await request(app)
        .post("/keys")
        .send({ keySource: "org", orgId: "org-1", provider: "anthropic", apiKey: "sk-ant-secret" });

      const res = await request(app)
        .get("/keys/anthropic/decrypt")
        .set(callerHeaders)
        .query({ keySource: "org", orgId: "org-1" });

      expect(res.status).toBe(200);
      expect(res.body.provider).toBe("anthropic");
      expect(res.body.key).toBe("sk-ant-secret");
    });

    it("GET /keys/:provider/decrypt — should return 404 for missing key", async () => {
      const res = await request(app)
        .get("/keys/anthropic/decrypt")
        .set(callerHeaders)
        .query({ keySource: "org", orgId: "org-missing" });

      expect(res.status).toBe(404);
      expect(res.body.error).toContain("anthropic");
    });

    it("GET /keys/:provider/decrypt — should reject missing caller headers", async () => {
      const res = await request(app)
        .get("/keys/anthropic/decrypt")
        .query({ keySource: "org", orgId: "org-1" });

      expect(res.status).toBe(400);
      expect(res.body.error).toContain("X-Caller-Service");
    });

    it("DELETE /keys/:provider — should delete an org key", async () => {
      await request(app)
        .post("/keys")
        .send({ keySource: "org", orgId: "org-1", provider: "anthropic", apiKey: "sk-ant-abc" });

      const res = await request(app)
        .delete("/keys/anthropic")
        .query({ keySource: "org", orgId: "org-1" });

      expect(res.status).toBe(200);

      const decryptRes = await request(app)
        .get("/keys/anthropic/decrypt")
        .set(callerHeaders)
        .query({ keySource: "org", orgId: "org-1" });

      expect(decryptRes.status).toBe(404);
    });
  });

  // ==================== APP KEYS ====================

  describe("keySource=app", () => {
    it("POST /keys — should create an app key", async () => {
      const res = await request(app)
        .post("/keys")
        .send({ keySource: "app", appId: "my-app", provider: "stripe", apiKey: "sk_test_abc" });

      expect(res.status).toBe(200);
      expect(res.body.provider).toBe("stripe");
      expect(res.body.maskedKey).toBeDefined();
    });

    it("POST /keys — should reject missing appId", async () => {
      const res = await request(app)
        .post("/keys")
        .send({ keySource: "app", provider: "stripe", apiKey: "sk_test_abc" });

      expect(res.status).toBe(400);
    });

    it("GET /keys — should list app keys", async () => {
      await request(app)
        .post("/keys")
        .send({ keySource: "app", appId: "my-app", provider: "stripe", apiKey: "sk_test_abc" });

      const res = await request(app)
        .get("/keys")
        .query({ keySource: "app", appId: "my-app" });

      expect(res.status).toBe(200);
      expect(res.body.keys).toHaveLength(1);
      expect(res.body.keys[0].provider).toBe("stripe");
    });

    it("GET /keys/:provider/decrypt — should return decrypted app key", async () => {
      await request(app)
        .post("/keys")
        .send({ keySource: "app", appId: "my-app", provider: "stripe", apiKey: "sk_live_secret" });

      const res = await request(app)
        .get("/keys/stripe/decrypt")
        .set(callerHeaders)
        .query({ keySource: "app", appId: "my-app" });

      expect(res.status).toBe(200);
      expect(res.body.provider).toBe("stripe");
      expect(res.body.key).toBe("sk_live_secret");
    });

    it("DELETE /keys/:provider — should delete an app key", async () => {
      await request(app)
        .post("/keys")
        .send({ keySource: "app", appId: "my-app", provider: "stripe", apiKey: "sk_test_abc" });

      const res = await request(app)
        .delete("/keys/stripe")
        .query({ keySource: "app", appId: "my-app" });

      expect(res.status).toBe(200);
    });
  });

  // ==================== PLATFORM KEYS ====================

  describe("keySource=platform", () => {
    it("POST /keys — should create a platform key", async () => {
      const res = await request(app)
        .post("/keys")
        .send({ keySource: "platform", provider: "anthropic", apiKey: "sk-ant-platform" });

      expect(res.status).toBe(200);
      expect(res.body.provider).toBe("anthropic");
    });

    it("GET /keys — should list platform keys", async () => {
      await request(app)
        .post("/keys")
        .send({ keySource: "platform", provider: "anthropic", apiKey: "sk-ant-platform" });

      const res = await request(app)
        .get("/keys")
        .query({ keySource: "platform" });

      expect(res.status).toBe(200);
      expect(res.body.keys).toHaveLength(1);
    });

    it("GET /keys/:provider/decrypt — should return decrypted platform key", async () => {
      await request(app)
        .post("/keys")
        .send({ keySource: "platform", provider: "anthropic", apiKey: "sk-ant-platform-secret" });

      const res = await request(app)
        .get("/keys/anthropic/decrypt")
        .set(callerHeaders)
        .query({ keySource: "platform" });

      expect(res.status).toBe(200);
      expect(res.body.key).toBe("sk-ant-platform-secret");
    });

    it("DELETE /keys/:provider — should delete a platform key", async () => {
      await request(app)
        .post("/keys")
        .send({ keySource: "platform", provider: "anthropic", apiKey: "sk-ant-platform" });

      const res = await request(app)
        .delete("/keys/anthropic")
        .query({ keySource: "platform" });

      expect(res.status).toBe(200);
    });
  });

  // ==================== BYOK ALIAS ====================

  describe("keySource=byok (legacy alias for org)", () => {
    it("POST /keys — should work with keySource=byok", async () => {
      const res = await request(app)
        .post("/keys")
        .send({ keySource: "byok", orgId: "org-1", provider: "anthropic", apiKey: "sk-ant-byok" });

      expect(res.status).toBe(200);
      expect(res.body.provider).toBe("anthropic");
    });

    it("GET /keys — should work with keySource=byok", async () => {
      await request(app)
        .post("/keys")
        .send({ keySource: "byok", orgId: "org-1", provider: "anthropic", apiKey: "sk-ant-byok" });

      const res = await request(app)
        .get("/keys")
        .query({ keySource: "byok", orgId: "org-1" });

      expect(res.status).toBe(200);
      expect(res.body.keys).toHaveLength(1);
    });

    it("GET /keys/:provider/decrypt — should work with keySource=byok", async () => {
      await request(app)
        .post("/keys")
        .send({ keySource: "byok", orgId: "org-1", provider: "anthropic", apiKey: "sk-ant-byok-secret" });

      const res = await request(app)
        .get("/keys/anthropic/decrypt")
        .set(callerHeaders)
        .query({ keySource: "byok", orgId: "org-1" });

      expect(res.status).toBe(200);
      expect(res.body.key).toBe("sk-ant-byok-secret");
    });

    it("should share the same store as keySource=org", async () => {
      await request(app)
        .post("/keys")
        .send({ keySource: "byok", orgId: "org-1", provider: "anthropic", apiKey: "sk-ant-shared" });

      const res = await request(app)
        .get("/keys/anthropic/decrypt")
        .set(callerHeaders)
        .query({ keySource: "org", orgId: "org-1" });

      expect(res.status).toBe(200);
      expect(res.body.key).toBe("sk-ant-shared");
    });
  });

  // ==================== VALIDATION ====================

  describe("validation errors", () => {
    it("should reject missing keySource", async () => {
      const res = await request(app)
        .get("/keys")
        .query({ orgId: "org-1" });

      expect(res.status).toBe(400);
    });

    it("should reject invalid keySource", async () => {
      const res = await request(app)
        .get("/keys")
        .query({ keySource: "invalid", orgId: "org-1" });

      expect(res.status).toBe(400);
    });
  });
});
