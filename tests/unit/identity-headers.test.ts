import { describe, it, expect } from "vitest";
import request from "supertest";
import express from "express";
import { requireIdentityHeaders } from "../../src/middleware/auth.js";

const app = express();
app.use(express.json());
// Mount under /internal to mirror real routing (req.path strips mount prefix)
app.use("/internal", requireIdentityHeaders, (_req, res) => {
  res.json({ ok: true });
});

describe("requireIdentityHeaders middleware", () => {
  it("should pass when both headers are present", async () => {
    const res = await request(app)
      .get("/internal/api-keys")
      .set({ "x-org-id": "org-1", "x-user-id": "user-1" });
    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
  });

  it("should reject missing x-org-id", async () => {
    const res = await request(app)
      .get("/internal/api-keys")
      .set({ "x-user-id": "user-1" });
    expect(res.status).toBe(400);
    expect(res.body.error).toContain("x-org-id");
  });

  it("should reject missing x-user-id", async () => {
    const res = await request(app)
      .get("/internal/api-keys")
      .set({ "x-org-id": "org-1" });
    expect(res.status).toBe(400);
    expect(res.body.error).toContain("x-user-id");
  });

  it("should reject empty x-org-id", async () => {
    const res = await request(app)
      .get("/internal/api-keys")
      .set({ "x-org-id": "  ", "x-user-id": "user-1" });
    expect(res.status).toBe(400);
    expect(res.body.error).toContain("x-org-id");
  });

  it("should reject empty x-user-id", async () => {
    const res = await request(app)
      .get("/internal/api-keys")
      .set({ "x-org-id": "org-1", "x-user-id": "" });
    expect(res.status).toBe(400);
    expect(res.body.error).toContain("x-user-id");
  });

  it("should reject when both headers are missing", async () => {
    const res = await request(app).get("/internal/api-keys");
    expect(res.status).toBe(400);
  });

  // System-level routes should NOT require identity headers
  it("should skip identity check for /platform-keys routes", async () => {
    const res = await request(app).post("/internal/platform-keys");
    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
  });

  it("should skip identity check for /platform-keys GET", async () => {
    const res = await request(app).get("/internal/platform-keys");
    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
  });

  it("should skip identity check for /platform-keys/:provider DELETE", async () => {
    const res = await request(app).delete("/internal/platform-keys/anthropic");
    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
  });

  it("should skip identity check for /provider-requirements", async () => {
    const res = await request(app).post("/internal/provider-requirements");
    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
  });

  // Ensure non-exempted routes still require headers
  it("should still require identity headers for /keys routes", async () => {
    const res = await request(app).get("/internal/keys");
    expect(res.status).toBe(400);
    expect(res.body.error).toContain("x-org-id");
  });
});
