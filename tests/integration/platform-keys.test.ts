import { describe, it, expect, beforeEach, afterAll } from "vitest";
import request from "supertest";
import express from "express";
import internalRoutes from "../../src/routes/internal.js";
import { cleanTestData, closeDb } from "../helpers/test-db.js";

const app = express();
app.use(express.json());
app.use("/internal", internalRoutes);

describe("Platform Keys endpoints", () => {
  beforeEach(async () => {
    await cleanTestData();
  });

  afterAll(async () => {
    await cleanTestData();
    await closeDb();
  });

  describe("POST /internal/platform-keys", () => {
    it("should create a new platform key", async () => {
      const res = await request(app)
        .post("/internal/platform-keys")
        .send({ provider: "anthropic", apiKey: "sk-ant-abc123" });

      expect(res.status).toBe(200);
      expect(res.body.provider).toBe("anthropic");
      expect(res.body.maskedKey).toBeDefined();
      expect(res.body.message).toContain("anthropic");
    });

    it("should upsert (update existing key)", async () => {
      await request(app)
        .post("/internal/platform-keys")
        .send({ provider: "anthropic", apiKey: "sk-ant-old" });

      const res = await request(app)
        .post("/internal/platform-keys")
        .send({ provider: "anthropic", apiKey: "sk-ant-new" });

      expect(res.status).toBe(200);
      expect(res.body.provider).toBe("anthropic");

      // Verify only one key exists by listing
      const listRes = await request(app)
        .get("/internal/platform-keys");

      expect(listRes.body.keys).toHaveLength(1);
    });

    it("should reject missing fields", async () => {
      const res = await request(app)
        .post("/internal/platform-keys")
        .send({ provider: "anthropic" });

      expect(res.status).toBe(400);
    });
  });

  describe("GET /internal/platform-keys", () => {
    it("should list platform keys (masked)", async () => {
      await request(app)
        .post("/internal/platform-keys")
        .send({ provider: "anthropic", apiKey: "sk-ant-abc123xyz" });
      await request(app)
        .post("/internal/platform-keys")
        .send({ provider: "openai", apiKey: "sk-proj-abc123xyz" });

      const res = await request(app)
        .get("/internal/platform-keys");

      expect(res.status).toBe(200);
      expect(res.body.keys).toHaveLength(2);
      for (const key of res.body.keys) {
        expect(key.maskedKey).toBeDefined();
        expect(key.maskedKey).not.toBe("sk-ant-abc123xyz");
        expect(key.maskedKey).not.toBe("sk-proj-abc123xyz");
      }
    });

    it("should return empty array when no keys exist", async () => {
      const res = await request(app)
        .get("/internal/platform-keys");

      expect(res.status).toBe(200);
      expect(res.body.keys).toHaveLength(0);
    });
  });

  describe("GET /internal/platform-keys/:provider/decrypt", () => {
    const callerHeaders = {
      "x-caller-service": "test-service",
      "x-caller-method": "POST",
      "x-caller-path": "/test/endpoint",
    };

    it("should return decrypted key", async () => {
      await request(app)
        .post("/internal/platform-keys")
        .send({ provider: "anthropic", apiKey: "sk-ant-secret123" });

      const res = await request(app)
        .get("/internal/platform-keys/anthropic/decrypt")
        .set(callerHeaders);

      expect(res.status).toBe(200);
      expect(res.body.provider).toBe("anthropic");
      expect(res.body.key).toBe("sk-ant-secret123");
    });

    it("should return 404 for unconfigured provider", async () => {
      const res = await request(app)
        .get("/internal/platform-keys/anthropic/decrypt")
        .set(callerHeaders);

      expect(res.status).toBe(404);
    });

    it("should reject missing caller headers", async () => {
      const res = await request(app)
        .get("/internal/platform-keys/anthropic/decrypt");

      expect(res.status).toBe(400);
      expect(res.body.error).toContain("X-Caller-Service");
    });

    it("should not require appId or orgId", async () => {
      await request(app)
        .post("/internal/platform-keys")
        .send({ provider: "anthropic", apiKey: "sk-ant-secret123" });

      // No appId, no orgId — just provider and caller headers
      const res = await request(app)
        .get("/internal/platform-keys/anthropic/decrypt")
        .set(callerHeaders);

      expect(res.status).toBe(200);
      expect(res.body.key).toBe("sk-ant-secret123");
    });
  });

  describe("DELETE /internal/platform-keys/:provider", () => {
    it("should delete a platform key", async () => {
      await request(app)
        .post("/internal/platform-keys")
        .send({ provider: "anthropic", apiKey: "sk-ant-abc" });

      const res = await request(app)
        .delete("/internal/platform-keys/anthropic");

      expect(res.status).toBe(200);
      expect(res.body.provider).toBe("anthropic");

      // Verify it's gone
      const decryptRes = await request(app)
        .get("/internal/platform-keys/anthropic/decrypt")
        .set({
          "x-caller-service": "test-service",
          "x-caller-method": "POST",
          "x-caller-path": "/test/endpoint",
        });

      expect(decryptRes.status).toBe(404);
    });

    it("should succeed even if key doesn't exist (idempotent)", async () => {
      const res = await request(app)
        .delete("/internal/platform-keys/anthropic");

      expect(res.status).toBe(200);
    });
  });
});
