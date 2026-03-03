import { describe, it, expect, beforeEach, afterAll } from "vitest";
import request from "supertest";
import express from "express";
import keysRoutes from "../../src/routes/keys.js";
import { requireIdentityHeaders } from "../../src/middleware/auth.js";
import { cleanTestData, closeDb } from "../helpers/test-db.js";

const app = express();
app.use(express.json());
app.use("/keys", requireIdentityHeaders, keysRoutes);

const identityHeaders = {
  "x-org-id": "org-123",
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

  describe("POST /keys", () => {
    it("should create a new org key", async () => {
      const res = await request(app)
        .post("/keys")
        .set(identityHeaders)
        .send({ provider: "anthropic", apiKey: "sk-ant-abc123" });

      expect(res.status).toBe(200);
      expect(res.body.provider).toBe("anthropic");
      expect(res.body.maskedKey).toBeDefined();
      expect(res.body.message).toContain("anthropic");
    });

    it("should upsert (update existing key)", async () => {
      await request(app)
        .post("/keys")
        .set(identityHeaders)
        .send({ provider: "anthropic", apiKey: "sk-ant-old" });

      const res = await request(app)
        .post("/keys")
        .set(identityHeaders)
        .send({ provider: "anthropic", apiKey: "sk-ant-new" });

      expect(res.status).toBe(200);
      expect(res.body.provider).toBe("anthropic");

      const listRes = await request(app)
        .get("/keys")
        .set(identityHeaders);

      expect(listRes.body.keys).toHaveLength(1);
    });

    it("should reject missing fields", async () => {
      const res = await request(app)
        .post("/keys")
        .set(identityHeaders)
        .send({});

      expect(res.status).toBe(400);
    });
  });

  describe("GET /keys", () => {
    it("should list org keys (masked)", async () => {
      await request(app)
        .post("/keys")
        .set(identityHeaders)
        .send({ provider: "anthropic", apiKey: "sk-ant-abc123xyz" });
      await request(app)
        .post("/keys")
        .set(identityHeaders)
        .send({ provider: "firecrawl", apiKey: "fc-abc123xyz" });

      const res = await request(app)
        .get("/keys")
        .set(identityHeaders);

      expect(res.status).toBe(200);
      expect(res.body.keys).toHaveLength(2);
      for (const key of res.body.keys) {
        expect(key.maskedKey).toBeDefined();
      }
    });

    it("should return empty array for unknown org", async () => {
      const res = await request(app)
        .get("/keys")
        .set({ "x-org-id": "nonexistent", "x-user-id": "test-user" });

      expect(res.status).toBe(200);
      expect(res.body.keys).toHaveLength(0);
    });

    it("should reject missing identity headers", async () => {
      const res = await request(app)
        .get("/keys");

      expect(res.status).toBe(400);
    });
  });

  describe("DELETE /keys/:provider", () => {
    it("should delete an org key", async () => {
      await request(app)
        .post("/keys")
        .set(identityHeaders)
        .send({ provider: "anthropic", apiKey: "sk-ant-abc" });

      const res = await request(app)
        .delete("/keys/anthropic")
        .set(identityHeaders);

      expect(res.status).toBe(200);
      expect(res.body.provider).toBe("anthropic");

      const listRes = await request(app)
        .get("/keys")
        .set(identityHeaders);

      expect(listRes.body.keys).toHaveLength(0);
    });

    it("should succeed even if key doesn't exist (idempotent)", async () => {
      const res = await request(app)
        .delete("/keys/anthropic")
        .set(identityHeaders);

      expect(res.status).toBe(200);
    });

    it("should reject missing identity headers", async () => {
      const res = await request(app)
        .delete("/keys/anthropic");

      expect(res.status).toBe(400);
    });
  });
});
