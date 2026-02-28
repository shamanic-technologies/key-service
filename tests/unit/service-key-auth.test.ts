import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import express from "express";
import request from "supertest";
import { serviceKeyAuth } from "../../src/middleware/auth.js";

function createApp() {
  const app = express();
  app.use(express.json());
  app.use("/internal", serviceKeyAuth, (_req, res) => {
    res.json({ ok: true });
  });
  return app;
}

describe("serviceKeyAuth middleware", () => {
  const VALID_KEY = "test-service-key-12345";

  beforeEach(() => {
    process.env.KEY_SERVICE_API_KEY = VALID_KEY;
  });

  afterEach(() => {
    delete process.env.KEY_SERVICE_API_KEY;
  });

  it("should pass with valid x-api-key header", async () => {
    const app = createApp();
    const res = await request(app)
      .get("/internal/keys/anthropic/decrypt")
      .set("x-api-key", VALID_KEY);

    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
  });

  it("should pass with valid Authorization Bearer header", async () => {
    const app = createApp();
    const res = await request(app)
      .get("/internal/keys/anthropic/decrypt")
      .set("authorization", `Bearer ${VALID_KEY}`);

    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
  });

  it("should reject missing auth headers", async () => {
    const app = createApp();
    const res = await request(app)
      .get("/internal/keys/anthropic/decrypt");

    expect(res.status).toBe(401);
    expect(res.body.error).toBe("Invalid service key");
  });

  it("should reject invalid key", async () => {
    const app = createApp();
    const res = await request(app)
      .get("/internal/keys/anthropic/decrypt")
      .set("x-api-key", "wrong-key");

    expect(res.status).toBe(401);
  });

  it("should handle key with trailing whitespace in env var", async () => {
    process.env.KEY_SERVICE_API_KEY = `${VALID_KEY}  \n`;
    const app = createApp();
    const res = await request(app)
      .get("/internal/keys/anthropic/decrypt")
      .set("x-api-key", VALID_KEY);

    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
  });

  it("should handle key with trailing whitespace in header", async () => {
    const app = createApp();
    const res = await request(app)
      .get("/internal/keys/anthropic/decrypt")
      .set("x-api-key", `${VALID_KEY}  `);

    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
  });

  it("should return 500 when KEY_SERVICE_API_KEY is not set", async () => {
    delete process.env.KEY_SERVICE_API_KEY;
    const app = createApp();
    const res = await request(app)
      .get("/internal/keys/anthropic/decrypt")
      .set("x-api-key", VALID_KEY);

    expect(res.status).toBe(500);
    expect(res.body.error).toBe("Service not configured");
  });

  it("should prefer x-api-key over authorization header", async () => {
    const app = createApp();
    const res = await request(app)
      .get("/internal/keys/anthropic/decrypt")
      .set("x-api-key", VALID_KEY)
      .set("authorization", "Bearer wrong-key");

    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
  });
});
