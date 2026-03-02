import { describe, it, expect, beforeEach, afterAll } from "vitest";
import request from "supertest";
import express from "express";
import keysRoutes from "../../src/routes/keys.js";
import internalRoutes from "../../src/routes/internal.js";
import { requireIdentityHeaders } from "../../src/middleware/auth.js";
import { cleanTestData, closeDb } from "../helpers/test-db.js";

const app = express();
app.use(express.json());
app.use("/keys", requireIdentityHeaders, keysRoutes);
app.use("/internal", requireIdentityHeaders, internalRoutes);

const identityHeaders = {
  "x-org-id": "test-org-id",
  "x-user-id": "test-user-id",
};

const callerHeaders = {
  "x-caller-service": "test-service",
  "x-caller-method": "POST",
  "x-caller-path": "/test/endpoint",
};

describe("/keys endpoints", () => {
  beforeEach(async () => {
    await cleanTestData();
  });

  afterAll(async () => {
    await cleanTestData();
    await closeDb();
  });

  // ==================== IDENTITY HEADERS ====================

  describe("identity headers enforcement", () => {
    it("should reject requests without x-org-id header", async () => {
      const res = await request(app)
        .get("/keys/anthropic/decrypt")
        .set({ ...callerHeaders, "x-user-id": "user-1" })
        .query({ orgId: "org-1", userId: "user-1" });

      expect(res.status).toBe(400);
      expect(res.body.error).toContain("x-org-id");
    });

    it("should reject requests without x-user-id header", async () => {
      const res = await request(app)
        .get("/keys/anthropic/decrypt")
        .set({ ...callerHeaders, "x-org-id": "org-1" })
        .query({ orgId: "org-1", userId: "user-1" });

      expect(res.status).toBe(400);
      expect(res.body.error).toContain("x-user-id");
    });
  });

  // ==================== DECRYPT (AUTO-RESOLVE) ====================

  describe("GET /keys/:provider/decrypt (auto-resolve)", () => {
    it("should default to platform key when no preference set", async () => {
      await request(app)
        .post("/internal/platform-keys")
        .set(identityHeaders)
        .send({ provider: "anthropic", apiKey: "sk-ant-platform-secret" });

      const res = await request(app)
        .get("/keys/anthropic/decrypt")
        .set({ ...identityHeaders, ...callerHeaders })
        .query({ orgId: "org-1", userId: "user-1" });

      expect(res.status).toBe(200);
      expect(res.body.key).toBe("sk-ant-platform-secret");
      expect(res.body.keySource).toBe("platform");
      expect(res.body.userId).toBe("user-1");
    });

    it("should use org key when preference is set to org", async () => {
      await request(app)
        .post("/internal/platform-keys")
        .set(identityHeaders)
        .send({ provider: "anthropic", apiKey: "sk-ant-platform" });
      await request(app)
        .post("/internal/keys")
        .set(identityHeaders)
        .send({ orgId: "org-1", provider: "anthropic", apiKey: "sk-ant-org-secret" });

      await request(app)
        .put("/keys/anthropic/source")
        .set(identityHeaders)
        .send({ orgId: "org-1", keySource: "org" });

      const res = await request(app)
        .get("/keys/anthropic/decrypt")
        .set({ ...identityHeaders, ...callerHeaders })
        .query({ orgId: "org-1", userId: "user-1" });

      expect(res.status).toBe(200);
      expect(res.body.key).toBe("sk-ant-org-secret");
      expect(res.body.keySource).toBe("org");
      expect(res.body.userId).toBe("user-1");
    });

    it("should switch back to platform when preference is changed", async () => {
      await request(app)
        .post("/internal/platform-keys")
        .set(identityHeaders)
        .send({ provider: "anthropic", apiKey: "sk-ant-platform" });
      await request(app)
        .post("/internal/keys")
        .set(identityHeaders)
        .send({ orgId: "org-1", provider: "anthropic", apiKey: "sk-ant-org" });

      await request(app)
        .put("/keys/anthropic/source")
        .set(identityHeaders)
        .send({ orgId: "org-1", keySource: "org" });
      await request(app)
        .put("/keys/anthropic/source")
        .set(identityHeaders)
        .send({ orgId: "org-1", keySource: "platform" });

      const res = await request(app)
        .get("/keys/anthropic/decrypt")
        .set({ ...identityHeaders, ...callerHeaders })
        .query({ orgId: "org-1", userId: "user-1" });

      expect(res.status).toBe(200);
      expect(res.body.key).toBe("sk-ant-platform");
      expect(res.body.keySource).toBe("platform");
    });

    it("should return 404 when no key exists for resolved source", async () => {
      const res = await request(app)
        .get("/keys/anthropic/decrypt")
        .set({ ...identityHeaders, ...callerHeaders })
        .query({ orgId: "org-1", userId: "user-1" });

      expect(res.status).toBe(404);
    });

    it("should reject missing caller headers", async () => {
      const res = await request(app)
        .get("/keys/anthropic/decrypt")
        .set(identityHeaders)
        .query({ orgId: "org-1", userId: "user-1" });

      expect(res.status).toBe(400);
      expect(res.body.error).toContain("X-Caller-Service");
    });

    it("should reject missing orgId", async () => {
      const res = await request(app)
        .get("/keys/anthropic/decrypt")
        .set({ ...identityHeaders, ...callerHeaders })
        .query({ userId: "user-1" });

      expect(res.status).toBe(400);
    });

    it("should reject missing userId", async () => {
      const res = await request(app)
        .get("/keys/anthropic/decrypt")
        .set({ ...identityHeaders, ...callerHeaders })
        .query({ orgId: "org-1" });

      expect(res.status).toBe(400);
    });
  });

  // ==================== KEY SOURCE PREFERENCES ====================

  describe("PUT /keys/:provider/source", () => {
    it("should set key source to org when org key exists", async () => {
      await request(app)
        .post("/internal/keys")
        .set(identityHeaders)
        .send({ orgId: "org-1", provider: "anthropic", apiKey: "sk-ant-org" });

      const res = await request(app)
        .put("/keys/anthropic/source")
        .set(identityHeaders)
        .send({ orgId: "org-1", keySource: "org" });

      expect(res.status).toBe(200);
      expect(res.body.provider).toBe("anthropic");
      expect(res.body.orgId).toBe("org-1");
      expect(res.body.keySource).toBe("org");
    });

    it("should reject switching to org when no org key stored", async () => {
      const res = await request(app)
        .put("/keys/anthropic/source")
        .set(identityHeaders)
        .send({ orgId: "org-1", keySource: "org" });

      expect(res.status).toBe(400);
      expect(res.body.error).toContain("No org key stored");
    });

    it("should allow switching to platform without any keys stored", async () => {
      const res = await request(app)
        .put("/keys/anthropic/source")
        .set(identityHeaders)
        .send({ orgId: "org-1", keySource: "platform" });

      expect(res.status).toBe(200);
      expect(res.body.keySource).toBe("platform");
    });

    it("should upsert preference (update on second call)", async () => {
      await request(app)
        .post("/internal/keys")
        .set(identityHeaders)
        .send({ orgId: "org-1", provider: "anthropic", apiKey: "sk-ant-org" });

      await request(app)
        .put("/keys/anthropic/source")
        .set(identityHeaders)
        .send({ orgId: "org-1", keySource: "org" });

      const res = await request(app)
        .put("/keys/anthropic/source")
        .set(identityHeaders)
        .send({ orgId: "org-1", keySource: "platform" });

      expect(res.status).toBe(200);
      expect(res.body.keySource).toBe("platform");
    });
  });

  describe("GET /keys/:provider/source", () => {
    it("should return platform as default when no preference set", async () => {
      const res = await request(app)
        .get("/keys/anthropic/source")
        .set(identityHeaders)
        .query({ orgId: "org-1" });

      expect(res.status).toBe(200);
      expect(res.body.provider).toBe("anthropic");
      expect(res.body.orgId).toBe("org-1");
      expect(res.body.keySource).toBe("platform");
      expect(res.body.isDefault).toBe(true);
    });

    it("should return explicit preference when set", async () => {
      await request(app)
        .post("/internal/keys")
        .set(identityHeaders)
        .send({ orgId: "org-1", provider: "anthropic", apiKey: "sk-ant-org" });
      await request(app)
        .put("/keys/anthropic/source")
        .set(identityHeaders)
        .send({ orgId: "org-1", keySource: "org" });

      const res = await request(app)
        .get("/keys/anthropic/source")
        .set(identityHeaders)
        .query({ orgId: "org-1" });

      expect(res.status).toBe(200);
      expect(res.body.keySource).toBe("org");
      expect(res.body.isDefault).toBe(false);
    });

    it("should reject missing orgId", async () => {
      const res = await request(app)
        .get("/keys/anthropic/source")
        .set(identityHeaders);

      expect(res.status).toBe(400);
    });
  });

  describe("GET /keys/sources", () => {
    it("should return empty when no preferences set", async () => {
      const res = await request(app)
        .get("/keys/sources")
        .set(identityHeaders)
        .query({ orgId: "org-1" });

      expect(res.status).toBe(200);
      expect(res.body.sources).toHaveLength(0);
    });

    it("should list all explicit preferences for an org", async () => {
      await request(app)
        .post("/internal/keys")
        .set(identityHeaders)
        .send({ orgId: "org-1", provider: "anthropic", apiKey: "sk-ant" });
      await request(app)
        .post("/internal/keys")
        .set(identityHeaders)
        .send({ orgId: "org-1", provider: "openai", apiKey: "sk-oai" });

      await request(app)
        .put("/keys/anthropic/source")
        .set(identityHeaders)
        .send({ orgId: "org-1", keySource: "org" });
      await request(app)
        .put("/keys/openai/source")
        .set(identityHeaders)
        .send({ orgId: "org-1", keySource: "org" });

      const res = await request(app)
        .get("/keys/sources")
        .set(identityHeaders)
        .query({ orgId: "org-1" });

      expect(res.status).toBe(200);
      expect(res.body.sources).toHaveLength(2);
      const providers = res.body.sources.map((s: { provider: string }) => s.provider).sort();
      expect(providers).toEqual(["anthropic", "openai"]);
    });

    it("should reject missing orgId", async () => {
      const res = await request(app)
        .get("/keys/sources")
        .set(identityHeaders);

      expect(res.status).toBe(400);
    });
  });
});
