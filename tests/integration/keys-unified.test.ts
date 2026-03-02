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

    it("DELETE /keys/:provider — should delete an org key", async () => {
      await request(app)
        .post("/keys")
        .send({ keySource: "org", orgId: "org-1", provider: "anthropic", apiKey: "sk-ant-abc" });

      const res = await request(app)
        .delete("/keys/anthropic")
        .query({ keySource: "org", orgId: "org-1" });

      expect(res.status).toBe(200);

      // Verify it's gone by listing
      const listRes = await request(app)
        .get("/keys")
        .query({ keySource: "org", orgId: "org-1" });

      expect(listRes.body.keys).toHaveLength(0);
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

    it("should share the same store as keySource=org", async () => {
      await request(app)
        .post("/keys")
        .send({ keySource: "byok", orgId: "org-1", provider: "anthropic", apiKey: "sk-ant-shared" });

      // List via org
      const res = await request(app)
        .get("/keys")
        .query({ keySource: "org", orgId: "org-1" });

      expect(res.status).toBe(200);
      expect(res.body.keys).toHaveLength(1);
    });
  });

  // ==================== DECRYPT (AUTO-RESOLVE) ====================

  describe("GET /keys/:provider/decrypt (auto-resolve)", () => {
    it("should default to platform key when no preference set", async () => {
      // Store a platform key
      await request(app)
        .post("/keys")
        .send({ keySource: "platform", provider: "anthropic", apiKey: "sk-ant-platform-secret" });

      const res = await request(app)
        .get("/keys/anthropic/decrypt")
        .set(callerHeaders)
        .query({ orgId: "org-1" });

      expect(res.status).toBe(200);
      expect(res.body.key).toBe("sk-ant-platform-secret");
      expect(res.body.keySource).toBe("platform");
    });

    it("should use org key when preference is set to org", async () => {
      // Store both keys
      await request(app)
        .post("/keys")
        .send({ keySource: "platform", provider: "anthropic", apiKey: "sk-ant-platform" });
      await request(app)
        .post("/keys")
        .send({ keySource: "org", orgId: "org-1", provider: "anthropic", apiKey: "sk-ant-org-secret" });

      // Set preference to org
      await request(app)
        .put("/keys/anthropic/source")
        .send({ orgId: "org-1", keySource: "org" });

      const res = await request(app)
        .get("/keys/anthropic/decrypt")
        .set(callerHeaders)
        .query({ orgId: "org-1" });

      expect(res.status).toBe(200);
      expect(res.body.key).toBe("sk-ant-org-secret");
      expect(res.body.keySource).toBe("org");
    });

    it("should switch back to platform when preference is changed", async () => {
      // Store both keys
      await request(app)
        .post("/keys")
        .send({ keySource: "platform", provider: "anthropic", apiKey: "sk-ant-platform" });
      await request(app)
        .post("/keys")
        .send({ keySource: "org", orgId: "org-1", provider: "anthropic", apiKey: "sk-ant-org" });

      // Set to org, then back to platform
      await request(app)
        .put("/keys/anthropic/source")
        .send({ orgId: "org-1", keySource: "org" });
      await request(app)
        .put("/keys/anthropic/source")
        .send({ orgId: "org-1", keySource: "platform" });

      const res = await request(app)
        .get("/keys/anthropic/decrypt")
        .set(callerHeaders)
        .query({ orgId: "org-1" });

      expect(res.status).toBe(200);
      expect(res.body.key).toBe("sk-ant-platform");
      expect(res.body.keySource).toBe("platform");
    });

    it("should return 404 when no key exists for resolved source", async () => {
      const res = await request(app)
        .get("/keys/anthropic/decrypt")
        .set(callerHeaders)
        .query({ orgId: "org-1" });

      expect(res.status).toBe(404);
    });

    it("should reject missing caller headers", async () => {
      const res = await request(app)
        .get("/keys/anthropic/decrypt")
        .query({ orgId: "org-1" });

      expect(res.status).toBe(400);
      expect(res.body.error).toContain("X-Caller-Service");
    });

    it("should reject missing orgId", async () => {
      const res = await request(app)
        .get("/keys/anthropic/decrypt")
        .set(callerHeaders);

      expect(res.status).toBe(400);
    });
  });

  // ==================== KEY SOURCE PREFERENCES ====================

  describe("PUT /keys/:provider/source", () => {
    it("should set key source to org when org key exists", async () => {
      // Store org key first
      await request(app)
        .post("/keys")
        .send({ keySource: "org", orgId: "org-1", provider: "anthropic", apiKey: "sk-ant-org" });

      const res = await request(app)
        .put("/keys/anthropic/source")
        .send({ orgId: "org-1", keySource: "org" });

      expect(res.status).toBe(200);
      expect(res.body.provider).toBe("anthropic");
      expect(res.body.orgId).toBe("org-1");
      expect(res.body.keySource).toBe("org");
    });

    it("should reject switching to org when no org key stored", async () => {
      const res = await request(app)
        .put("/keys/anthropic/source")
        .send({ orgId: "org-1", keySource: "org" });

      expect(res.status).toBe(400);
      expect(res.body.error).toContain("No org key stored");
    });

    it("should allow switching to platform without any keys stored", async () => {
      const res = await request(app)
        .put("/keys/anthropic/source")
        .send({ orgId: "org-1", keySource: "platform" });

      expect(res.status).toBe(200);
      expect(res.body.keySource).toBe("platform");
    });

    it("should upsert preference (update on second call)", async () => {
      await request(app)
        .post("/keys")
        .send({ keySource: "org", orgId: "org-1", provider: "anthropic", apiKey: "sk-ant-org" });

      // Set to org
      await request(app)
        .put("/keys/anthropic/source")
        .send({ orgId: "org-1", keySource: "org" });

      // Update to platform
      const res = await request(app)
        .put("/keys/anthropic/source")
        .send({ orgId: "org-1", keySource: "platform" });

      expect(res.status).toBe(200);
      expect(res.body.keySource).toBe("platform");
    });
  });

  describe("GET /keys/:provider/source", () => {
    it("should return platform as default when no preference set", async () => {
      const res = await request(app)
        .get("/keys/anthropic/source")
        .query({ orgId: "org-1" });

      expect(res.status).toBe(200);
      expect(res.body.provider).toBe("anthropic");
      expect(res.body.orgId).toBe("org-1");
      expect(res.body.keySource).toBe("platform");
      expect(res.body.isDefault).toBe(true);
    });

    it("should return explicit preference when set", async () => {
      await request(app)
        .post("/keys")
        .send({ keySource: "org", orgId: "org-1", provider: "anthropic", apiKey: "sk-ant-org" });
      await request(app)
        .put("/keys/anthropic/source")
        .send({ orgId: "org-1", keySource: "org" });

      const res = await request(app)
        .get("/keys/anthropic/source")
        .query({ orgId: "org-1" });

      expect(res.status).toBe(200);
      expect(res.body.keySource).toBe("org");
      expect(res.body.isDefault).toBe(false);
    });

    it("should reject missing orgId", async () => {
      const res = await request(app)
        .get("/keys/anthropic/source");

      expect(res.status).toBe(400);
    });
  });

  describe("GET /keys/sources", () => {
    it("should return empty when no preferences set", async () => {
      const res = await request(app)
        .get("/keys/sources")
        .query({ orgId: "org-1" });

      expect(res.status).toBe(200);
      expect(res.body.sources).toHaveLength(0);
    });

    it("should list all explicit preferences for an org", async () => {
      // Store org keys
      await request(app)
        .post("/keys")
        .send({ keySource: "org", orgId: "org-1", provider: "anthropic", apiKey: "sk-ant" });
      await request(app)
        .post("/keys")
        .send({ keySource: "org", orgId: "org-1", provider: "openai", apiKey: "sk-oai" });

      // Set preferences
      await request(app)
        .put("/keys/anthropic/source")
        .send({ orgId: "org-1", keySource: "org" });
      await request(app)
        .put("/keys/openai/source")
        .send({ orgId: "org-1", keySource: "org" });

      const res = await request(app)
        .get("/keys/sources")
        .query({ orgId: "org-1" });

      expect(res.status).toBe(200);
      expect(res.body.sources).toHaveLength(2);
      const providers = res.body.sources.map((s: { provider: string }) => s.provider).sort();
      expect(providers).toEqual(["anthropic", "openai"]);
    });

    it("should reject missing orgId", async () => {
      const res = await request(app)
        .get("/keys/sources");

      expect(res.status).toBe(400);
    });
  });

  // ==================== VALIDATION ====================

  describe("validation errors", () => {
    it("should reject missing keySource on list", async () => {
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
