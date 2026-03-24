import { describe, it, expect } from "vitest";
import request from "supertest";
import express from "express";
import { captureTrackingHeaders } from "../../src/middleware/auth.js";

function createApp() {
  const app = express();
  app.use(express.json());
  app.use(captureTrackingHeaders);
  app.get("/test", (req, res) => {
    res.json({ tracking: req.tracking ?? null });
  });
  return app;
}

describe("captureTrackingHeaders middleware", () => {
  const app = createApp();

  it("should set req.tracking when all tracking headers present", async () => {
    const res = await request(app)
      .get("/test")
      .set({
        "x-campaign-id": "camp-1",
        "x-brand-id": "brand-1",
        "x-workflow-name": "wf-1",
        "x-feature-slug": "press-outreach",
      });
    expect(res.status).toBe(200);
    expect(res.body.tracking).toEqual({
      campaignId: "camp-1",
      brandId: "brand-1",
      workflowName: "wf-1",
      featureSlug: "press-outreach",
    });
  });

  it("should set req.tracking to null when no tracking headers present", async () => {
    const res = await request(app).get("/test");
    expect(res.status).toBe(200);
    expect(res.body.tracking).toBeNull();
  });

  it("should set partial tracking when only some headers present", async () => {
    const res = await request(app)
      .get("/test")
      .set({ "x-campaign-id": "camp-1" });
    expect(res.status).toBe(200);
    expect(res.body.tracking).toEqual({ campaignId: "camp-1" });
  });

  it("should never reject — tracking headers are optional", async () => {
    const res = await request(app)
      .get("/test")
      .set({ "x-campaign-id": "", "x-brand-id": "", "x-workflow-name": "", "x-feature-slug": "" });
    expect(res.status).toBe(200);
    expect(res.body.tracking).toBeNull();
  });
});
