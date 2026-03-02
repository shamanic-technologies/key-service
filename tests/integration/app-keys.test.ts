import { describe, it, expect, beforeEach, afterAll } from "vitest";
import request from "supertest";
import express from "express";
import internalRoutes from "../../src/routes/internal.js";
import { cleanTestData, closeDb, insertTestAppKey } from "../helpers/test-db.js";
import { encrypt } from "../../src/lib/crypto.js";

const app = express();
app.use(express.json());
app.use("/internal", internalRoutes);

describe("App Keys endpoints", () => {
  beforeEach(async () => {
    await cleanTestData();
  });

  afterAll(async () => {
    await cleanTestData();
    await closeDb();
  });

  describe("POST /internal/app-keys", () => {
    it("should create a new app key", async () => {
      const res = await request(app)
        .post("/internal/app-keys")
        .send({ appId: "polaritycourse", provider: "stripe", apiKey: "sk_live_abc123" });

      expect(res.status).toBe(200);
      expect(res.body.provider).toBe("stripe");
      expect(res.body.maskedKey).toBeDefined();
      expect(res.body.message).toContain("stripe");
    });

    it("should upsert (update existing key)", async () => {
      await request(app)
        .post("/internal/app-keys")
        .send({ appId: "myapp", provider: "stripe", apiKey: "sk_live_old" });

      const res = await request(app)
        .post("/internal/app-keys")
        .send({ appId: "myapp", provider: "stripe", apiKey: "sk_live_new" });

      expect(res.status).toBe(200);
      expect(res.body.provider).toBe("stripe");

      // Verify only one key exists by listing
      const listRes = await request(app)
        .get("/internal/app-keys")
        .query({ appId: "myapp" });

      expect(listRes.body.keys).toHaveLength(1);
    });

    it("should reject missing fields", async () => {
      const res = await request(app)
        .post("/internal/app-keys")
        .send({ appId: "myapp" });

      expect(res.status).toBe(400);
    });
  });

  describe("GET /internal/app-keys", () => {
    it("should list app keys (masked)", async () => {
      await request(app)
        .post("/internal/app-keys")
        .send({ appId: "myapp", provider: "stripe", apiKey: "sk_live_abc123xyz" });
      await request(app)
        .post("/internal/app-keys")
        .send({ appId: "myapp", provider: "openai", apiKey: "sk-proj-abc123xyz" });

      const res = await request(app)
        .get("/internal/app-keys")
        .query({ appId: "myapp" });

      expect(res.status).toBe(200);
      expect(res.body.keys).toHaveLength(2);
      // Keys should be masked, not plaintext
      for (const key of res.body.keys) {
        expect(key.maskedKey).toBeDefined();
        expect(key.maskedKey).not.toBe("sk_live_abc123xyz");
        expect(key.maskedKey).not.toBe("sk-proj-abc123xyz");
      }
    });

    it("should return empty array for unknown app", async () => {
      const res = await request(app)
        .get("/internal/app-keys")
        .query({ appId: "nonexistent" });

      expect(res.status).toBe(200);
      expect(res.body.keys).toHaveLength(0);
    });

    it("should reject missing appId", async () => {
      const res = await request(app).get("/internal/app-keys");

      expect(res.status).toBe(400);
    });
  });

  describe("GET /internal/app-keys/:provider/decrypt", () => {
    const callerHeaders = {
      "x-caller-service": "test-service",
      "x-caller-method": "POST",
      "x-caller-path": "/test/endpoint",
    };

    it("should return decrypted key", async () => {
      await request(app)
        .post("/internal/app-keys")
        .send({ appId: "myapp", provider: "stripe", apiKey: "sk_live_secret123" });

      const res = await request(app)
        .get("/internal/app-keys/stripe/decrypt")
        .set(callerHeaders)
        .query({ appId: "myapp" });

      expect(res.status).toBe(200);
      expect(res.body.provider).toBe("stripe");
      expect(res.body.key).toBe("sk_live_secret123");
    });

    it("should return 404 with clear 'App key not found' message", async () => {
      const res = await request(app)
        .get("/internal/app-keys/stripe/decrypt")
        .set(callerHeaders)
        .query({ appId: "myapp" });

      expect(res.status).toBe(404);
      expect(res.body.error).toContain("App key not found");
      expect(res.body.error).toContain("stripe");
      expect(res.body.error).toContain("myapp");
    });

    it("should reject missing appId", async () => {
      const res = await request(app)
        .get("/internal/app-keys/stripe/decrypt")
        .set(callerHeaders);

      expect(res.status).toBe(400);
    });

    it("should reject missing caller headers", async () => {
      const res = await request(app)
        .get("/internal/app-keys/stripe/decrypt")
        .query({ appId: "myapp" });

      expect(res.status).toBe(400);
      expect(res.body.error).toContain("X-Caller-Service");
    });
  });

  describe("DELETE /internal/app-keys/:provider", () => {
    it("should delete an app key", async () => {
      await request(app)
        .post("/internal/app-keys")
        .send({ appId: "myapp", provider: "stripe", apiKey: "sk_live_abc" });

      const res = await request(app)
        .delete("/internal/app-keys/stripe")
        .query({ appId: "myapp" });

      expect(res.status).toBe(200);
      expect(res.body.provider).toBe("stripe");

      // Verify it's gone
      const decryptRes = await request(app)
        .get("/internal/app-keys/stripe/decrypt")
        .set({
          "x-caller-service": "test-service",
          "x-caller-method": "POST",
          "x-caller-path": "/test/endpoint",
        })
        .query({ appId: "myapp" });

      expect(decryptRes.status).toBe(404);
    });

    it("should succeed even if key doesn't exist (idempotent)", async () => {
      const res = await request(app)
        .delete("/internal/app-keys/stripe")
        .query({ appId: "myapp" });

      expect(res.status).toBe(200);
    });

    it("should reject missing appId", async () => {
      const res = await request(app)
        .delete("/internal/app-keys/stripe");

      expect(res.status).toBe(400);
    });
  });
});
