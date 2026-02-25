import { describe, it, expect, beforeEach, afterAll } from "vitest";
import request from "supertest";
import express from "express";
import { eq, and } from "drizzle-orm";
import internalRoutes from "../../src/routes/internal.js";
import { db } from "../../src/db/index.js";
import { providerRequirements } from "../../src/db/schema.js";
import {
  cleanTestData,
  closeDb,
  insertTestProviderRequirement,
} from "../helpers/test-db.js";

const app = express();
app.use(express.json());
app.use("/internal", internalRoutes);

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

  describe("Caller header validation on BYOK decrypt", () => {
    it("should return 400 without caller headers on BYOK decrypt", async () => {
      const res = await request(app)
        .get("/internal/keys/apollo/decrypt")
        .query({ clerkOrgId: "org_test" });

      expect(res.status).toBe(400);
      expect(res.body.error).toContain("X-Caller-Service");
    });

    it("should return 400 with partial caller headers", async () => {
      const res = await request(app)
        .get("/internal/keys/apollo/decrypt")
        .set({ "x-caller-service": "apollo" })
        .query({ clerkOrgId: "org_test" });

      expect(res.status).toBe(400);
      expect(res.body.error).toContain("X-Caller-Service");
    });
  });

  describe("Caller header validation on app key decrypt", () => {
    it("should return 400 without caller headers on app key decrypt", async () => {
      const res = await request(app)
        .get("/internal/app-keys/stripe/decrypt")
        .query({ appId: "myapp" });

      expect(res.status).toBe(400);
      expect(res.body.error).toContain("X-Caller-Service");
    });
  });

  // ==================== Provider requirement recording ====================

  describe("Provider requirement recording", () => {
    it("should record a provider requirement on app key decrypt", async () => {
      // Create an app key first
      await request(app)
        .post("/internal/app-keys")
        .send({ appId: "myapp", provider: "stripe", apiKey: "sk_live_test" });

      // Decrypt with caller headers
      const res = await request(app)
        .get("/internal/app-keys/stripe/decrypt")
        .set({
          "x-caller-service": "payment-service",
          "x-caller-method": "POST",
          "x-caller-path": "/payments/charge",
        })
        .query({ appId: "myapp" });

      expect(res.status).toBe(200);

      // Verify the requirement was recorded
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

    it("should update lastSeenAt on repeat calls (upsert)", async () => {
      await request(app)
        .post("/internal/app-keys")
        .send({ appId: "myapp", provider: "stripe", apiKey: "sk_live_test" });

      // First call
      await request(app)
        .get("/internal/app-keys/stripe/decrypt")
        .set(callerHeaders)
        .query({ appId: "myapp" });

      const firstReqs = await db.query.providerRequirements.findMany();
      expect(firstReqs).toHaveLength(1);
      const firstSeenAt = firstReqs[0].lastSeenAt;

      // Wait a moment to ensure timestamp changes
      await new Promise((resolve) => setTimeout(resolve, 50));

      // Second call
      await request(app)
        .get("/internal/app-keys/stripe/decrypt")
        .set(callerHeaders)
        .query({ appId: "myapp" });

      const secondReqs = await db.query.providerRequirements.findMany();
      expect(secondReqs).toHaveLength(1); // Still 1 row, not 2
      expect(secondReqs[0].lastSeenAt.getTime()).toBeGreaterThanOrEqual(firstSeenAt.getTime());
    });

    it("should record multiple providers for the same endpoint", async () => {
      await request(app)
        .post("/internal/app-keys")
        .send({ appId: "myapp", provider: "openai", apiKey: "sk-test1" });
      await request(app)
        .post("/internal/app-keys")
        .send({ appId: "myapp", provider: "anthropic", apiKey: "sk-ant-test1" });

      // Same caller, different providers
      await request(app)
        .get("/internal/app-keys/openai/decrypt")
        .set(callerHeaders)
        .query({ appId: "myapp" });

      await request(app)
        .get("/internal/app-keys/anthropic/decrypt")
        .set(callerHeaders)
        .query({ appId: "myapp" });

      const reqs = await db.query.providerRequirements.findMany({
        where: eq(providerRequirements.service, "apollo"),
      });

      expect(reqs).toHaveLength(2);
      const providers = reqs.map((r) => r.provider).sort();
      expect(providers).toEqual(["anthropic", "openai"]);
    });

    it("should not record when key is not found (404)", async () => {
      const res = await request(app)
        .get("/internal/app-keys/stripe/decrypt")
        .set(callerHeaders)
        .query({ appId: "nonexistent" });

      expect(res.status).toBe(404);

      const reqs = await db.query.providerRequirements.findMany();
      expect(reqs).toHaveLength(0);
    });
  });

  // ==================== POST /internal/provider-requirements ====================

  describe("POST /internal/provider-requirements", () => {
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
        .post("/internal/provider-requirements")
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
        .post("/internal/provider-requirements")
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
        .post("/internal/provider-requirements")
        .send({
          endpoints: [
            { service: "apollo", method: "POST", path: "/leads/search" },
            { service: "apollo", method: "GET", path: "/leads/enrich" },
          ],
        });

      expect(res.status).toBe(200);
      expect(res.body.requirements).toHaveLength(2);
      expect(res.body.providers).toEqual(["apollo"]); // Deduplicated
    });

    it("should normalize service to lowercase and method to uppercase", async () => {
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
            { service: "Apollo", method: "post", path: "/leads/search" },
          ],
        });

      expect(res.status).toBe(200);
      expect(res.body.requirements).toHaveLength(1);
      expect(res.body.providers).toEqual(["apollo"]);
    });

    it("should return 400 for invalid request body", async () => {
      const res = await request(app)
        .post("/internal/provider-requirements")
        .send({});

      expect(res.status).toBe(400);
    });

    it("should return 400 for empty endpoints array", async () => {
      const res = await request(app)
        .post("/internal/provider-requirements")
        .send({ endpoints: [] });

      expect(res.status).toBe(400);
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

      // Only query for apollo endpoint
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
  });
});
