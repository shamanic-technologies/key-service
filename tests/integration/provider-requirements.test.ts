import { describe, it, expect, beforeEach, afterAll } from "vitest";
import request from "supertest";
import express from "express";
import { eq, and } from "drizzle-orm";
import keysRoutes from "../../src/routes/keys.js";
import platformKeysRoutes from "../../src/routes/platform-keys.js";
import providerRequirementsRoutes from "../../src/routes/provider-requirements.js";
import { requireIdentityHeaders } from "../../src/middleware/auth.js";
import { db } from "../../src/db/index.js";
import { providerRequirements } from "../../src/db/schema.js";
import {
  cleanTestData,
  closeDb,
  insertTestProviderRequirement,
} from "../helpers/test-db.js";

const app = express();
app.use(express.json());
app.use("/keys", requireIdentityHeaders, keysRoutes);
app.use("/platform-keys", platformKeysRoutes);
app.use("/provider-requirements", providerRequirementsRoutes);
app.use("/internal/provider-requirements", providerRequirementsRoutes);

const identityHeaders = {
  "x-org-id": "test-org-id",
  "x-user-id": "test-user-id",
};

const callerHeaders = {
  "x-caller-service": "apollo",
  "x-caller-method": "POST",
  "x-caller-path": "/leads/search",
};

describe("Provider Requirements", () => {
  beforeEach(async () => {
    await cleanTestData();
  });

  afterAll(async () => {
    await cleanTestData();
    await closeDb();
  });

  // ==================== Caller header validation ====================

  describe("Caller header validation on key decrypt", () => {
    it("should return 400 without caller headers on auto-resolve decrypt", async () => {
      const res = await request(app)
        .get("/keys/apollo/decrypt")
        .set(identityHeaders);

      expect(res.status).toBe(400);
      expect(res.body.error).toContain("X-Caller-Service");
    });

    it("should return 400 with partial caller headers", async () => {
      const res = await request(app)
        .get("/keys/apollo/decrypt")
        .set({ ...identityHeaders, "x-caller-service": "apollo" });

      expect(res.status).toBe(400);
      expect(res.body.error).toContain("X-Caller-Service");
    });
  });

  describe("Caller header validation on platform key decrypt", () => {
    it("should return 400 without caller headers on platform key decrypt", async () => {
      const res = await request(app)
        .get("/keys/platform/stripe/decrypt")
        .set(identityHeaders);

      expect(res.status).toBe(400);
      expect(res.body.error).toContain("X-Caller-Service");
    });
  });

  // ==================== Provider requirement recording ====================

  describe("Provider requirement recording", () => {
    it("should record a provider requirement on org key decrypt", async () => {
      await request(app)
        .post("/keys")
        .set(identityHeaders)
        .send({ provider: "stripe", apiKey: "sk_live_test" });

      // Set preference to "org" so auto-resolve uses the org key
      await request(app)
        .put("/keys/stripe/source")
        .set(identityHeaders)
        .send({ keySource: "org" });

      const res = await request(app)
        .get("/keys/stripe/decrypt")
        .set({
          ...identityHeaders,
          "x-caller-service": "payment-service",
          "x-caller-method": "POST",
          "x-caller-path": "/payments/charge",
        });

      expect(res.status).toBe(200);

      const reqs = await db.query.providerRequirements.findMany({
        where: and(
          eq(providerRequirements.service, "payment-service"),
          eq(providerRequirements.provider, "stripe")
        ),
      });

      expect(reqs).toHaveLength(1);
      expect(reqs[0].method).toBe("POST");
      expect(reqs[0].path).toBe("/payments/charge");
    });

    it("should record a provider requirement on platform key decrypt", async () => {
      await request(app)
        .post("/platform-keys")
        .send({ provider: "anthropic", apiKey: "sk-ant-test" });

      const res = await request(app)
        .get("/keys/platform/anthropic/decrypt")
        .set({
          ...identityHeaders,
          "x-caller-service": "ai-service",
          "x-caller-method": "POST",
          "x-caller-path": "/generate",
        });

      expect(res.status).toBe(200);

      const reqs = await db.query.providerRequirements.findMany({
        where: and(
          eq(providerRequirements.service, "ai-service"),
          eq(providerRequirements.provider, "anthropic")
        ),
      });

      expect(reqs).toHaveLength(1);
      expect(reqs[0].method).toBe("POST");
      expect(reqs[0].path).toBe("/generate");
    });

    it("should update lastSeenAt on repeat calls (upsert)", async () => {
      await request(app)
        .post("/platform-keys")
        .send({ provider: "stripe", apiKey: "sk_live_test" });

      await request(app)
        .get("/keys/platform/stripe/decrypt")
        .set({ ...identityHeaders, ...callerHeaders });

      const firstReqs = await db.query.providerRequirements.findMany();
      expect(firstReqs).toHaveLength(1);
      const firstSeenAt = firstReqs[0].lastSeenAt;

      await new Promise((resolve) => setTimeout(resolve, 50));

      await request(app)
        .get("/keys/platform/stripe/decrypt")
        .set({ ...identityHeaders, ...callerHeaders });

      const secondReqs = await db.query.providerRequirements.findMany();
      expect(secondReqs).toHaveLength(1);
      expect(secondReqs[0].lastSeenAt.getTime()).toBeGreaterThanOrEqual(firstSeenAt.getTime());
    });

    it("should record multiple providers for the same endpoint", async () => {
      await request(app)
        .post("/platform-keys")
        .send({ provider: "openai", apiKey: "sk-test1" });
      await request(app)
        .post("/platform-keys")
        .send({ provider: "anthropic", apiKey: "sk-ant-test1" });

      await request(app)
        .get("/keys/platform/openai/decrypt")
        .set({ ...identityHeaders, ...callerHeaders });

      await request(app)
        .get("/keys/platform/anthropic/decrypt")
        .set({ ...identityHeaders, ...callerHeaders });

      const reqs = await db.query.providerRequirements.findMany({
        where: eq(providerRequirements.service, "apollo"),
      });

      expect(reqs).toHaveLength(2);
      const providerNames = reqs.map((r) => r.provider).sort();
      expect(providerNames).toEqual(["anthropic", "openai"]);
    });

    it("should not record when key is not found (404)", async () => {
      const res = await request(app)
        .get("/keys/platform/stripe/decrypt")
        .set({ ...identityHeaders, ...callerHeaders });

      expect(res.status).toBe(404);

      const reqs = await db.query.providerRequirements.findMany();
      expect(reqs).toHaveLength(0);
    });
  });

  // ==================== POST /provider-requirements ====================

  describe("POST /provider-requirements", () => {
    it("should return matching requirements for known endpoints", async () => {
      await insertTestProviderRequirement({
        service: "apollo",
        method: "POST",
        path: "/leads/search",
        provider: "apollo",
      });
      await insertTestProviderRequirement({
        service: "firecrawl",
        method: "POST",
        path: "/scrape",
        provider: "firecrawl",
      });

      const res = await request(app)
        .post("/provider-requirements")
        .send({
          endpoints: [
            { service: "apollo", method: "POST", path: "/leads/search" },
            { service: "firecrawl", method: "POST", path: "/scrape" },
          ],
        });

      expect(res.status).toBe(200);
      expect(res.body.requirements).toHaveLength(2);
      expect(res.body.providers).toEqual(["apollo", "firecrawl"]);
    });

    it("should return empty for unknown endpoints", async () => {
      const res = await request(app)
        .post("/provider-requirements")
        .send({
          endpoints: [
            { service: "unknown", method: "GET", path: "/nothing" },
          ],
        });

      expect(res.status).toBe(200);
      expect(res.body.requirements).toHaveLength(0);
      expect(res.body.providers).toHaveLength(0);
    });

    it("should deduplicate providers", async () => {
      await insertTestProviderRequirement({
        service: "apollo",
        method: "POST",
        path: "/leads/search",
        provider: "apollo",
      });
      await insertTestProviderRequirement({
        service: "apollo",
        method: "GET",
        path: "/leads/enrich",
        provider: "apollo",
      });

      const res = await request(app)
        .post("/provider-requirements")
        .send({
          endpoints: [
            { service: "apollo", method: "POST", path: "/leads/search" },
            { service: "apollo", method: "GET", path: "/leads/enrich" },
          ],
        });

      expect(res.status).toBe(200);
      expect(res.body.requirements).toHaveLength(2);
      expect(res.body.providers).toEqual(["apollo"]);
    });

    it("should normalize service to lowercase and method to uppercase", async () => {
      await insertTestProviderRequirement({
        service: "apollo",
        method: "POST",
        path: "/leads/search",
        provider: "apollo",
      });

      const res = await request(app)
        .post("/provider-requirements")
        .send({
          endpoints: [
            { service: "Apollo", method: "post", path: "/leads/search" },
          ],
        });

      expect(res.status).toBe(200);
      expect(res.body.requirements).toHaveLength(1);
      expect(res.body.providers).toEqual(["apollo"]);
    });

    it("should return 400 for invalid request body", async () => {
      const res = await request(app)
        .post("/provider-requirements")
        .send({});

      expect(res.status).toBe(400);
    });

    it("should return 400 for empty endpoints array", async () => {
      const res = await request(app)
        .post("/provider-requirements")
        .send({ endpoints: [] });

      expect(res.status).toBe(400);
    });

    it("should work at /internal/provider-requirements (backward compat)", async () => {
      await insertTestProviderRequirement({
        service: "apollo",
        method: "POST",
        path: "/leads/search",
        provider: "apollo",
      });

      const res = await request(app)
        .post("/internal/provider-requirements")
        .send({
          endpoints: [
            { service: "apollo", method: "POST", path: "/leads/search" },
          ],
        });

      expect(res.status).toBe(200);
      expect(res.body.requirements).toHaveLength(1);
      expect(res.body.providers).toEqual(["apollo"]);
    });

    it("should only return providers for matching endpoints, not all", async () => {
      await insertTestProviderRequirement({
        service: "apollo",
        method: "POST",
        path: "/leads/search",
        provider: "apollo",
      });
      await insertTestProviderRequirement({
        service: "firecrawl",
        method: "POST",
        path: "/scrape",
        provider: "firecrawl",
      });

      const res = await request(app)
        .post("/provider-requirements")
        .send({
          endpoints: [
            { service: "apollo", method: "POST", path: "/leads/search" },
          ],
        });

      expect(res.status).toBe(200);
      expect(res.body.requirements).toHaveLength(1);
      expect(res.body.providers).toEqual(["apollo"]);
    });
  });
});
