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
// Platform decrypt mounted before /keys — no identity headers (matches prod routing)
app.use("/keys/platform", platformDecryptRoutes);
app.use("/keys", requireIdentityHeaders, keysRoutes);
app.use("/platform-keys", platformKeysRoutes);

const identityHeaders = {
  "x-org-id": "org-1",
  "x-user-id": "user-1",
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
        .set({ ...callerHeaders, "x-user-id": "user-1" });

      expect(res.status).toBe(400);
      expect(res.body.error).toContain("x-org-id");
    });

    it("should reject requests without x-user-id header", async () => {
      const res = await request(app)
        .get("/keys/anthropic/decrypt")
        .set({ ...callerHeaders, "x-org-id": "org-1" });

      expect(res.status).toBe(400);
      expect(res.body.error).toContain("x-user-id");
    });
  });

  // ==================== PLATFORM DECRYPT (DIRECT) ====================

  describe("GET /keys/platform/:provider/decrypt (direct)", () => {
    it("should return decrypted platform key without identity headers", async () => {
      await request(app)
        .post("/platform-keys")
        .send({ provider: "stripe", apiKey: "sk_live_stripe_secret" });

      const res = await request(app)
        .get("/keys/platform/stripe/decrypt")
        .set(callerHeaders);

      expect(res.status).toBe(200);
      expect(res.body.provider).toBe("stripe");
      expect(res.body.key).toBe("sk_live_stripe_secret");
    });

    it("should return 404 when no platform key exists", async () => {
      const res = await request(app)
        .get("/keys/platform/stripe/decrypt")
        .set(callerHeaders);

      expect(res.status).toBe(404);
      expect(res.body.error).toContain("Platform key not found");
      expect(res.body.error).toContain("stripe");
    });

    it("should reject missing caller headers", async () => {
      const res = await request(app)
        .get("/keys/platform/stripe/decrypt");

      expect(res.status).toBe(400);
      expect(res.body.error).toContain("X-Caller-Service");
    });

    it("should not require orgId or userId headers", async () => {
      await request(app)
        .post("/platform-keys")
        .send({ provider: "stripe", apiKey: "sk_live_stripe_no_org" });

      // Only caller headers — no identity headers
      const res = await request(app)
        .get("/keys/platform/stripe/decrypt")
        .set(callerHeaders);

      expect(res.status).toBe(200);
      expect(res.body.key).toBe("sk_live_stripe_no_org");
      expect(res.body.provider).toBe("stripe");
    });
  });

  // ==================== DECRYPT (AUTO-RESOLVE) ====================

  describe("GET /keys/:provider/decrypt (auto-resolve)", () => {
    it("should default to platform key when no preference set", async () => {
      await request(app)
        .post("/platform-keys")
        .send({ provider: "anthropic", apiKey: "sk-ant-platform-secret" });

      const res = await request(app)
        .get("/keys/anthropic/decrypt")
        .set({ ...identityHeaders, ...callerHeaders });

      expect(res.status).toBe(200);
      expect(res.body.key).toBe("sk-ant-platform-secret");
      expect(res.body.keySource).toBe("platform");
      expect(res.body.userId).toBe("user-1");
    });

    it("should use org key when preference is set to org", async () => {
      await request(app)
        .post("/platform-keys")
        .send({ provider: "anthropic", apiKey: "sk-ant-platform" });
      await request(app)
        .post("/keys")
        .set(identityHeaders)
        .send({ provider: "anthropic", apiKey: "sk-ant-org-secret" });

      await request(app)
        .put("/keys/anthropic/source")
        .set(identityHeaders)
        .send({ keySource: "org" });

      const res = await request(app)
        .get("/keys/anthropic/decrypt")
        .set({ ...identityHeaders, ...callerHeaders });

      expect(res.status).toBe(200);
      expect(res.body.key).toBe("sk-ant-org-secret");
      expect(res.body.keySource).toBe("org");
      expect(res.body.userId).toBe("user-1");
    });

    it("should switch back to platform when preference is changed", async () => {
      await request(app)
        .post("/platform-keys")
        .send({ provider: "anthropic", apiKey: "sk-ant-platform" });
      await request(app)
        .post("/keys")
        .set(identityHeaders)
        .send({ provider: "anthropic", apiKey: "sk-ant-org" });

      await request(app)
        .put("/keys/anthropic/source")
        .set(identityHeaders)
        .send({ keySource: "org" });
      await request(app)
        .put("/keys/anthropic/source")
        .set(identityHeaders)
        .send({ keySource: "platform" });

      const res = await request(app)
        .get("/keys/anthropic/decrypt")
        .set({ ...identityHeaders, ...callerHeaders });

      expect(res.status).toBe(200);
      expect(res.body.key).toBe("sk-ant-platform");
      expect(res.body.keySource).toBe("platform");
    });

    it("should return 404 when no key exists for resolved source", async () => {
      const res = await request(app)
        .get("/keys/anthropic/decrypt")
        .set({ ...identityHeaders, ...callerHeaders });

      expect(res.status).toBe(404);
    });

    it("should reject missing caller headers", async () => {
      const res = await request(app)
        .get("/keys/anthropic/decrypt")
        .set(identityHeaders);

      expect(res.status).toBe(400);
      expect(res.body.error).toContain("X-Caller-Service");
    });
  });

  // ==================== KEY SOURCE PREFERENCES ====================

  describe("PUT /keys/:provider/source", () => {
    it("should set key source to org when org key exists", async () => {
      await request(app)
        .post("/keys")
        .set(identityHeaders)
        .send({ provider: "anthropic", apiKey: "sk-ant-org" });

      const res = await request(app)
        .put("/keys/anthropic/source")
        .set(identityHeaders)
        .send({ keySource: "org" });

      expect(res.status).toBe(200);
      expect(res.body.provider).toBe("anthropic");
      expect(res.body.orgId).toBe("org-1");
      expect(res.body.keySource).toBe("org");
    });

    it("should reject switching to org when no org key stored", async () => {
      const res = await request(app)
        .put("/keys/anthropic/source")
        .set(identityHeaders)
        .send({ keySource: "org" });

      expect(res.status).toBe(400);
      expect(res.body.error).toContain("No org key stored");
    });

    it("should allow switching to platform without any keys stored", async () => {
      const res = await request(app)
        .put("/keys/anthropic/source")
        .set(identityHeaders)
        .send({ keySource: "platform" });

      expect(res.status).toBe(200);
      expect(res.body.keySource).toBe("platform");
    });

    it("should upsert preference (update on second call)", async () => {
      await request(app)
        .post("/keys")
        .set(identityHeaders)
        .send({ provider: "anthropic", apiKey: "sk-ant-org" });

      await request(app)
        .put("/keys/anthropic/source")
        .set(identityHeaders)
        .send({ keySource: "org" });

      const res = await request(app)
        .put("/keys/anthropic/source")
        .set(identityHeaders)
        .send({ keySource: "platform" });

      expect(res.status).toBe(200);
      expect(res.body.keySource).toBe("platform");
    });
  });

  describe("GET /keys/:provider/source", () => {
    it("should return platform as default when no preference set", async () => {
      const res = await request(app)
        .get("/keys/anthropic/source")
        .set(identityHeaders);

      expect(res.status).toBe(200);
      expect(res.body.provider).toBe("anthropic");
      expect(res.body.orgId).toBe("org-1");
      expect(res.body.keySource).toBe("platform");
      expect(res.body.isDefault).toBe(true);
    });

    it("should return explicit preference when set", async () => {
      await request(app)
        .post("/keys")
        .set(identityHeaders)
        .send({ provider: "anthropic", apiKey: "sk-ant-org" });
      await request(app)
        .put("/keys/anthropic/source")
        .set(identityHeaders)
        .send({ keySource: "org" });

      const res = await request(app)
        .get("/keys/anthropic/source")
        .set(identityHeaders);

      expect(res.status).toBe(200);
      expect(res.body.keySource).toBe("org");
      expect(res.body.isDefault).toBe(false);
    });
  });

  describe("GET /keys/sources", () => {
    it("should return empty when no preferences set", async () => {
      const res = await request(app)
        .get("/keys/sources")
        .set(identityHeaders);

      expect(res.status).toBe(200);
      expect(res.body.sources).toHaveLength(0);
    });

    it("should list all explicit preferences for an org", async () => {
      await request(app)
        .post("/keys")
        .set(identityHeaders)
        .send({ provider: "anthropic", apiKey: "sk-ant" });
      await request(app)
        .post("/keys")
        .set(identityHeaders)
        .send({ provider: "openai", apiKey: "sk-oai" });

      await request(app)
        .put("/keys/anthropic/source")
        .set(identityHeaders)
        .send({ keySource: "org" });
      await request(app)
        .put("/keys/openai/source")
        .set(identityHeaders)
        .send({ keySource: "org" });

      const res = await request(app)
        .get("/keys/sources")
        .set(identityHeaders);

      expect(res.status).toBe(200);
      expect(res.body.sources).toHaveLength(2);
      const providers = res.body.sources.map((s: { provider: string }) => s.provider).sort();
      expect(providers).toEqual(["anthropic", "openai"]);
    });
  });
});
