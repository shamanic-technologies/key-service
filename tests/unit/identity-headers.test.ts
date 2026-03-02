import { describe, it, expect } from "vitest";
import request from "supertest";
import express from "express";
import { requireIdentityHeaders } from "../../src/middleware/auth.js";

const app = express();
app.use(express.json());
app.use(requireIdentityHeaders, (_req, res) => {
  res.json({ ok: true });
});

describe("requireIdentityHeaders middleware", () => {
  it("should pass when both headers are present", async () => {
    const res = await request(app)
      .get("/")
      .set({ "x-org-id": "org-1", "x-user-id": "user-1" });
    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
  });

  it("should reject missing x-org-id", async () => {
    const res = await request(app)
      .get("/")
      .set({ "x-user-id": "user-1" });
    expect(res.status).toBe(400);
    expect(res.body.error).toContain("x-org-id");
  });

  it("should reject missing x-user-id", async () => {
    const res = await request(app)
      .get("/")
      .set({ "x-org-id": "org-1" });
    expect(res.status).toBe(400);
    expect(res.body.error).toContain("x-user-id");
  });

  it("should reject empty x-org-id", async () => {
    const res = await request(app)
      .get("/")
      .set({ "x-org-id": "  ", "x-user-id": "user-1" });
    expect(res.status).toBe(400);
    expect(res.body.error).toContain("x-org-id");
  });

  it("should reject empty x-user-id", async () => {
    const res = await request(app)
      .get("/")
      .set({ "x-org-id": "org-1", "x-user-id": "" });
    expect(res.status).toBe(400);
    expect(res.body.error).toContain("x-user-id");
  });

  it("should reject when both headers are missing", async () => {
    const res = await request(app).get("/");
    expect(res.status).toBe(400);
  });
});
