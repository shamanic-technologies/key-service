import { describe, it, expect, beforeEach, afterAll } from "vitest";
import request from "supertest";
import express from "express";
import internalRoutes from "../../src/routes/internal.js";
import { requireIdentityHeaders } from "../../src/middleware/auth.js";
import { cleanTestData, closeDb } from "../helpers/test-db.js";

const app = express();
app.use(express.json());
app.use("/internal", requireIdentityHeaders, internalRoutes);

const identityHeaders = {
  "x-org-id": "test-org-id",
  "x-user-id": "test-user-id",
};

describe("Org Keys endpoints", () => {
  beforeEach(async () => {
    await cleanTestData();
  });

  afterAll(async () => {
    await cleanTestData();
    await closeDb();
  });

  describe("POST /internal/keys", () => {
    it("should create a new org key", async () => {
      const res = await request(app)
        .post("/internal/keys")
        .set(identityHeaders)
        .send({ orgId: "org-123", provider: "anthropic", apiKey: "sk-ant-abc123" });

      expect(res.status).toBe(200);
      expect(res.body.provider).toBe("anthropic");
      expect(res.body.maskedKey).toBeDefined();
      expect(res.body.message).toContain("anthropic");
    });

    it("should upsert (update existing key)", async () => {
      await request(app)
        .post("/internal/keys")
        .set(identityHeaders)
        .send({ orgId: "org-123", provider: "anthropic", apiKey: "sk-ant-old" });

      const res = await request(app)
        .post("/internal/keys")
        .set(identityHeaders)
        .send({ orgId: "org-123", provider: "anthropic", apiKey: "sk-ant-new" });

      expect(res.status).toBe(200);
      expect(res.body.provider).toBe("anthropic");

      const listRes = await request(app)
        .get("/internal/keys")
        .set(identityHeaders)
        .query({ orgId: "org-123" });

      expect(listRes.body.keys).toHaveLength(1);
    });

    it("should reject missing fields", async () => {
      const res = await request(app)
        .post("/internal/keys")
        .set(identityHeaders)
        .send({ orgId: "org-123" });

      expect(res.status).toBe(400);
    });
  });

  describe("GET /internal/keys", () => {
    it("should list org keys (masked)", async () => {
      await request(app)
        .post("/internal/keys")
        .set(identityHeaders)
        .send({ orgId: "org-123", provider: "anthropic", apiKey: "sk-ant-abc123xyz" });
      await request(app)
        .post("/internal/keys")
        .set(identityHeaders)
        .send({ orgId: "org-123", provider: "firecrawl", apiKey: "fc-abc123xyz" });

      const res = await request(app)
        .get("/internal/keys")
        .set(identityHeaders)
        .query({ orgId: "org-123" });

      expect(res.status).toBe(200);
      expect(res.body.keys).toHaveLength(2);
      for (const key of res.body.keys) {
        expect(key.maskedKey).toBeDefined();
      }
    });

    it("should return empty array for unknown org", async () => {
      const res = await request(app)
        .get("/internal/keys")
        .set(identityHeaders)
        .query({ orgId: "nonexistent" });

      expect(res.status).toBe(200);
      expect(res.body.keys).toHaveLength(0);
    });

    it("should reject missing orgId", async () => {
      const res = await request(app)
        .get("/internal/keys")
        .set(identityHeaders);

      expect(res.status).toBe(400);
    });
  });

  describe("GET /internal/keys/:provider/decrypt", () => {
    const callerHeaders = {
      "x-caller-service": "brand-service",
      "x-caller-method": "GET",
      "x-caller-path": "/brands/generate",
    };

    it("should return decrypted org key", async () => {
      await request(app)
        .post("/internal/keys")
        .set(identityHeaders)
        .send({ orgId: "org-123", provider: "anthropic", apiKey: "sk-ant-secret123" });

      const res = await request(app)
        .get("/internal/keys/anthropic/decrypt")
        .set({ ...identityHeaders, ...callerHeaders })
        .query({ orgId: "org-123" });

      expect(res.status).toBe(200);
      expect(res.body.provider).toBe("anthropic");
      expect(res.body.key).toBe("sk-ant-secret123");
    });

    it("should return 404 with clear 'Org key not found' message", async () => {
      const res = await request(app)
        .get("/internal/keys/anthropic/decrypt")
        .set({ ...identityHeaders, ...callerHeaders })
        .query({ orgId: "org-missing" });

      expect(res.status).toBe(404);
      expect(res.body.error).toContain("Org key not found");
      expect(res.body.error).toContain("anthropic");
      expect(res.body.error).toContain("org-missing");
    });

    it("should reject missing orgId", async () => {
      const res = await request(app)
        .get("/internal/keys/anthropic/decrypt")
        .set({ ...identityHeaders, ...callerHeaders });

      expect(res.status).toBe(400);
    });

    it("should reject missing caller headers", async () => {
      const res = await request(app)
        .get("/internal/keys/anthropic/decrypt")
        .set(identityHeaders)
        .query({ orgId: "org-123" });

      expect(res.status).toBe(400);
      expect(res.body.error).toContain("X-Caller-Service");
    });
  });

  describe("DELETE /internal/keys/:provider", () => {
    it("should delete an org key", async () => {
      await request(app)
        .post("/internal/keys")
        .set(identityHeaders)
        .send({ orgId: "org-123", provider: "anthropic", apiKey: "sk-ant-abc" });

      const res = await request(app)
        .delete("/internal/keys/anthropic")
        .set(identityHeaders)
        .query({ orgId: "org-123" });

      expect(res.status).toBe(200);
      expect(res.body.provider).toBe("anthropic");

      const decryptRes = await request(app)
        .get("/internal/keys/anthropic/decrypt")
        .set({
          ...identityHeaders,
          "x-caller-service": "test-service",
          "x-caller-method": "POST",
          "x-caller-path": "/test/endpoint",
        })
        .query({ orgId: "org-123" });

      expect(decryptRes.status).toBe(404);
    });

    it("should succeed even if key doesn't exist (idempotent)", async () => {
      const res = await request(app)
        .delete("/internal/keys/anthropic")
        .set(identityHeaders)
        .query({ orgId: "org-123" });

      expect(res.status).toBe(200);
    });

    it("should reject missing orgId", async () => {
      const res = await request(app)
        .delete("/internal/keys/anthropic")
        .set(identityHeaders);

      expect(res.status).toBe(400);
    });
  });
});
