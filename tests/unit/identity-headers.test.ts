import { describe, it, expect } from "vitest";
import request from "supertest";
import express from "express";
import { requireIdentityHeaders } from "../../src/middleware/auth.js";

function createApp() {
  const app = express();
  app.use(express.json());
  // Apply identity headers middleware to a test route group
  app.use("/protected", requireIdentityHeaders, (req, res) => {
    res.json({ ok: true, identity: req.identity });
  });
  return app;
}

describe("requireIdentityHeaders middleware", () => {
  const app = createApp();

  it("should pass when both headers are present and set req.identity", async () => {
    const res = await request(app)
      .get("/protected/anything")
      .set({ "x-org-id": "org-1", "x-user-id": "user-1" });
    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
    expect(res.body.identity).toEqual({ orgId: "org-1", userId: "user-1" });
  });

  it("should reject missing x-org-id", async () => {
    const res = await request(app)
      .get("/protected/anything")
      .set({ "x-user-id": "user-1" });
    expect(res.status).toBe(400);
    expect(res.body.error).toContain("x-org-id");
  });

  it("should reject missing x-user-id", async () => {
    const res = await request(app)
      .get("/protected/anything")
      .set({ "x-org-id": "org-1" });
    expect(res.status).toBe(400);
    expect(res.body.error).toContain("x-user-id");
  });

  it("should reject empty x-org-id", async () => {
    const res = await request(app)
      .get("/protected/anything")
      .set({ "x-org-id": "  ", "x-user-id": "user-1" });
    expect(res.status).toBe(400);
    expect(res.body.error).toContain("x-org-id");
  });

  it("should reject empty x-user-id", async () => {
    const res = await request(app)
      .get("/protected/anything")
      .set({ "x-org-id": "org-1", "x-user-id": "" });
    expect(res.status).toBe(400);
    expect(res.body.error).toContain("x-user-id");
  });

  it("should reject when both headers are missing", async () => {
    const res = await request(app).get("/protected/anything");
    expect(res.status).toBe(400);
  });

  it("should trim whitespace from header values", async () => {
    const res = await request(app)
      .get("/protected/anything")
      .set({ "x-org-id": "  org-1  ", "x-user-id": "  user-1  " });
    expect(res.status).toBe(200);
    expect(res.body.identity).toEqual({ orgId: "org-1", userId: "user-1" });
  });
});
