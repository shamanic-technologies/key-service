import { describe, it, expect, beforeEach, afterAll } from "vitest";
import request from "supertest";
import express from "express";
import platformKeysRoutes from "../../src/routes/platform-keys.js";
import { cleanTestData, closeDb } from "../helpers/test-db.js";

const app = express();
app.use(express.json());
// No identity headers middleware — platform keys don't need org/user context
app.use("/platform-keys", platformKeysRoutes);

describe("Platform Keys endpoints", () => {
  beforeEach(async () => {
    await cleanTestData();
  });

  afterAll(async () => {
    await cleanTestData();
    await closeDb();
  });

  describe("POST /platform-keys", () => {
    it("should create a new platform key", async () => {
      const res = await request(app)
        .post("/platform-keys")
        .send({ provider: "anthropic", apiKey: "sk-ant-abc123" });

      expect(res.status).toBe(200);
      expect(res.body.provider).toBe("anthropic");
      expect(res.body.maskedKey).toBeDefined();
      expect(res.body.message).toContain("anthropic");
    });

    it("should work without identity headers (cold-start bootstrap)", async () => {
      const res = await request(app)
        .post("/platform-keys")
        .send({ provider: "anthropic", apiKey: "sk-ant-bootstrap" });

      expect(res.status).toBe(200);
      expect(res.body.provider).toBe("anthropic");
      expect(res.body.maskedKey).toBeDefined();
    });

    it("should upsert (update existing key)", async () => {
      await request(app)
        .post("/platform-keys")
        .send({ provider: "anthropic", apiKey: "sk-ant-old" });

      const res = await request(app)
        .post("/platform-keys")
        .send({ provider: "anthropic", apiKey: "sk-ant-new" });

      expect(res.status).toBe(200);
      expect(res.body.provider).toBe("anthropic");

      const listRes = await request(app)
        .get("/platform-keys");

      expect(listRes.body.keys).toHaveLength(1);
    });

    it("should reject missing fields", async () => {
      const res = await request(app)
        .post("/platform-keys")
        .send({ provider: "anthropic" });

      expect(res.status).toBe(400);
    });
  });

  describe("GET /platform-keys", () => {
    it("should list platform keys (masked)", async () => {
      await request(app)
        .post("/platform-keys")
        .send({ provider: "anthropic", apiKey: "sk-ant-abc123xyz" });
      await request(app)
        .post("/platform-keys")
        .send({ provider: "openai", apiKey: "sk-proj-abc123xyz" });

      const res = await request(app)
        .get("/platform-keys");

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
        .get("/platform-keys");

      expect(res.status).toBe(200);
      expect(res.body.keys).toHaveLength(0);
    });
  });

  describe("DELETE /platform-keys/:provider", () => {
    it("should delete a platform key", async () => {
      await request(app)
        .post("/platform-keys")
        .send({ provider: "anthropic", apiKey: "sk-ant-abc" });

      const res = await request(app)
        .delete("/platform-keys/anthropic");

      expect(res.status).toBe(200);
      expect(res.body.provider).toBe("anthropic");

      const listRes = await request(app)
        .get("/platform-keys");

      expect(listRes.body.keys).toHaveLength(0);
    });

    it("should succeed even if key doesn't exist (idempotent)", async () => {
      const res = await request(app)
        .delete("/platform-keys/anthropic");

      expect(res.status).toBe(200);
    });
  });
});
