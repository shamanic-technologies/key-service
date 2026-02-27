import { describe, it, expect, beforeAll, beforeEach, afterAll } from "vitest";
import request from "supertest";
import express from "express";
import { serviceKeyAuth } from "../../src/middleware/auth.js";
import { apiKeyAuth } from "../../src/middleware/auth.js";
import internalRoutes from "../../src/routes/internal.js";
import validateRoutes from "../../src/routes/validate.js";
import { cleanTestData, closeDb } from "../helpers/test-db.js";

const SERVICE_KEY = "test-service-key-123";

function createApp() {
  const app = express();
  app.use(express.json());
  app.use(validateRoutes);
  app.use("/internal", serviceKeyAuth, internalRoutes);
  return app;
}

describe("App Registration", () => {
  let app: ReturnType<typeof createApp>;

  beforeAll(() => {
    process.env.KEY_SERVICE_API_KEY = SERVICE_KEY;
    app = createApp();
  });

  beforeEach(async () => {
    await cleanTestData();
  });

  afterAll(async () => {
    await cleanTestData();
    await closeDb();
  });

  describe("POST /internal/apps", () => {
    it("should register a new app and return an API key", async () => {
      const res = await request(app)
        .post("/internal/apps")
        .set("x-api-key", SERVICE_KEY)
        .send({ name: "test-app" });

      expect(res.status).toBe(200);
      expect(res.body.appId).toBe("test-app");
      expect(res.body.apiKey).toMatch(/^mcpf_app_/);
      expect(res.body.created).toBe(true);
    });

    it("should return existing app without full key on duplicate registration", async () => {
      // First registration
      const first = await request(app)
        .post("/internal/apps")
        .set("x-api-key", SERVICE_KEY)
        .send({ name: "duplicate-app" });

      expect(first.body.created).toBe(true);
      const originalKey = first.body.apiKey;

      // Second registration (same name)
      const second = await request(app)
        .post("/internal/apps")
        .set("x-api-key", SERVICE_KEY)
        .send({ name: "duplicate-app" });

      expect(second.status).toBe(200);
      expect(second.body.created).toBe(false);
      expect(second.body.appId).toBe("duplicate-app");
      expect(second.body.apiKey).toBeUndefined(); // No full key on duplicate
    });

    it("should reject invalid app name", async () => {
      const res = await request(app)
        .post("/internal/apps")
        .set("x-api-key", SERVICE_KEY)
        .send({ name: "Invalid Name With Spaces!" });

      expect(res.status).toBe(400);
    });

    it("should reject empty name", async () => {
      const res = await request(app)
        .post("/internal/apps")
        .set("x-api-key", SERVICE_KEY)
        .send({ name: "" });

      expect(res.status).toBe(400);
    });
  });

  describe("GET /validate with app key", () => {
    it("should validate an app key and return type app with appId", async () => {
      // Register app
      const reg = await request(app)
        .post("/internal/apps")
        .set("x-api-key", SERVICE_KEY)
        .send({ name: "validate-test-app" });

      const appKey = reg.body.apiKey;

      // Validate
      const res = await request(app)
        .get("/validate")
        .set("Authorization", `Bearer ${appKey}`);

      expect(res.status).toBe(200);
      expect(res.body.valid).toBe(true);
      expect(res.body.type).toBe("app");
      expect(res.body.appId).toBe("validate-test-app");
      expect(res.body.orgId).toBeUndefined();
    });

    it("should reject invalid app key", async () => {
      const res = await request(app)
        .get("/validate")
        .set("Authorization", "Bearer mcpf_app_0000000000000000000000000000000000000000");

      expect(res.status).toBe(401);
    });
  });
});
