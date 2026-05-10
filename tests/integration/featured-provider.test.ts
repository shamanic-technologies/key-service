import { describe, it, expect, beforeEach, afterAll } from "vitest";
import request from "supertest";
import express from "express";
import keysRoutes from "../../src/routes/keys.js";
import platformKeysRoutes from "../../src/routes/platform-keys.js";
import platformDecryptRoutes from "../../src/routes/platform-decrypt.js";
import { requireIdentityHeaders } from "../../src/middleware/auth.js";
import { cleanTestData, closeDb } from "../helpers/test-db.js";

const app = express();
app.use(express.json());
app.use("/keys/platform", platformDecryptRoutes);
app.use("/keys", requireIdentityHeaders, keysRoutes);
app.use("/platform-keys", platformKeysRoutes);

const identityHeaders = {
  "x-org-id": "org-featured",
  "x-user-id": "user-featured",
};

const callerHeaders = {
  "x-caller-service": "journalists-quotes-service",
  "x-caller-method": "POST",
  "x-caller-path": "/quotes/search",
};

const featuredCreds = { username: "press@example.com", password: "s3cret-p@ss" };

describe("featured provider — username+password JSON-object value", () => {
  beforeEach(async () => {
    await cleanTestData();
  });

  afterAll(async () => {
    await cleanTestData();
    await closeDb();
  });

  describe("POST /platform-keys with object apiKey", () => {
    it("accepts {username,password} object for featured provider", async () => {
      const res = await request(app)
        .post("/platform-keys")
        .send({ provider: "featured", apiKey: featuredCreds });

      expect(res.status).toBe(200);
      expect(res.body.provider).toBe("featured");
      expect(typeof res.body.maskedKey).toBe("string");
      expect(res.body.maskedKey).not.toContain("s3cret-p@ss");
    });

    it("rejects featured payload missing password", async () => {
      const res = await request(app)
        .post("/platform-keys")
        .send({ provider: "featured", apiKey: { username: "press@example.com" } });

      expect(res.status).toBe(400);
    });

    it("rejects featured payload with empty username", async () => {
      const res = await request(app)
        .post("/platform-keys")
        .send({ provider: "featured", apiKey: { username: "", password: "x" } });

      expect(res.status).toBe(400);
    });
  });

  describe("GET /keys/platform/featured/decrypt", () => {
    it("returns the {username,password} object intact", async () => {
      await request(app)
        .post("/platform-keys")
        .send({ provider: "featured", apiKey: featuredCreds });

      const res = await request(app)
        .get("/keys/platform/featured/decrypt")
        .set(callerHeaders);

      expect(res.status).toBe(200);
      expect(res.body.provider).toBe("featured");
      expect(res.body.key).toEqual(featuredCreds);
    });
  });

  describe("POST /keys (org-scoped) with object apiKey", () => {
    it("accepts featured object for an org", async () => {
      const res = await request(app)
        .post("/keys")
        .set(identityHeaders)
        .send({ provider: "featured", apiKey: featuredCreds });

      expect(res.status).toBe(200);
      expect(res.body.provider).toBe("featured");
      expect(res.body.maskedKey).not.toContain("s3cret-p@ss");
    });
  });

  describe("GET /keys/featured/decrypt (auto-resolve)", () => {
    it("returns object from platform key by default", async () => {
      await request(app)
        .post("/platform-keys")
        .send({ provider: "featured", apiKey: featuredCreds });

      const res = await request(app)
        .get("/keys/featured/decrypt")
        .set({ ...identityHeaders, ...callerHeaders });

      expect(res.status).toBe(200);
      expect(res.body.key).toEqual(featuredCreds);
      expect(res.body.keySource).toBe("platform");
    });

    it("returns org object after switching source to org", async () => {
      const orgCreds = { username: "org@brand.com", password: "org-pw-99" };

      await request(app)
        .post("/platform-keys")
        .send({ provider: "featured", apiKey: featuredCreds });
      await request(app)
        .post("/keys")
        .set(identityHeaders)
        .send({ provider: "featured", apiKey: orgCreds });
      await request(app)
        .put("/keys/featured/source")
        .set(identityHeaders)
        .send({ keySource: "org" });

      const res = await request(app)
        .get("/keys/featured/decrypt")
        .set({ ...identityHeaders, ...callerHeaders });

      expect(res.status).toBe(200);
      expect(res.body.key).toEqual(orgCreds);
      expect(res.body.keySource).toBe("org");
    });
  });

  describe("backward compatibility — string-value providers unchanged", () => {
    it("string apiKey still accepted and decrypted as string", async () => {
      await request(app)
        .post("/platform-keys")
        .send({ provider: "anthropic", apiKey: "sk-ant-stringval" });

      const res = await request(app)
        .get("/keys/platform/anthropic/decrypt")
        .set(callerHeaders);

      expect(res.status).toBe(200);
      expect(typeof res.body.key).toBe("string");
      expect(res.body.key).toBe("sk-ant-stringval");
    });
  });
});
