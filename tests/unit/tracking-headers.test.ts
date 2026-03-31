import { describe, it, expect } from "vitest";
import { extractTrackingHeaders } from "../../src/lib/tracking-headers.js";

function mockRequest(headers: Record<string, string | undefined>) {
  return { headers } as any;
}

describe("extractTrackingHeaders", () => {
  it("should return all fields when all headers present", () => {
    const result = extractTrackingHeaders(
      mockRequest({
        "x-campaign-id": "camp-123",
        "x-brand-id": "brand-456",
        "x-workflow-slug": "lead-enrichment",
        "x-feature-slug": "press-outreach",
      })
    );

    expect(result).toEqual({
      campaignId: "camp-123",
      brandIds: ["brand-456"],
      workflowSlug: "lead-enrichment",
      featureSlug: "press-outreach",
    });
  });

  it("should return null when no tracking headers present", () => {
    const result = extractTrackingHeaders(mockRequest({}));
    expect(result).toBeNull();
  });

  it("should return partial result when only some headers present", () => {
    const result = extractTrackingHeaders(
      mockRequest({
        "x-campaign-id": "camp-123",
      })
    );

    expect(result).toEqual({ campaignId: "camp-123" });
  });

  it("should return partial result with two headers", () => {
    const result = extractTrackingHeaders(
      mockRequest({
        "x-brand-id": "brand-456",
        "x-workflow-slug": "my-workflow",
      })
    );

    expect(result).toEqual({ brandIds: ["brand-456"], workflowSlug: "my-workflow" });
  });

  it("should extract x-feature-slug alone", () => {
    const result = extractTrackingHeaders(
      mockRequest({
        "x-feature-slug": "press-outreach",
      })
    );

    expect(result).toEqual({ featureSlug: "press-outreach" });
  });

  it("should ignore empty string headers", () => {
    const result = extractTrackingHeaders(
      mockRequest({
        "x-campaign-id": "",
        "x-brand-id": "brand-456",
        "x-workflow-slug": "",
      })
    );

    expect(result).toEqual({ brandIds: ["brand-456"] });
  });

  it("should ignore whitespace-only headers", () => {
    const result = extractTrackingHeaders(
      mockRequest({
        "x-campaign-id": "  ",
        "x-brand-id": "brand-456",
      })
    );

    expect(result).toEqual({ brandIds: ["brand-456"] });
  });

  it("should return null when all headers are empty", () => {
    const result = extractTrackingHeaders(
      mockRequest({
        "x-campaign-id": "",
        "x-brand-id": "",
        "x-workflow-slug": "",
        "x-feature-slug": "",
      })
    );

    expect(result).toBeNull();
  });

  it("should trim whitespace from values", () => {
    const result = extractTrackingHeaders(
      mockRequest({
        "x-campaign-id": "  camp-123  ",
        "x-brand-id": "  brand-456  ",
        "x-workflow-slug": "  my-workflow  ",
        "x-feature-slug": "  press-outreach  ",
      })
    );

    expect(result).toEqual({
      campaignId: "camp-123",
      brandIds: ["brand-456"],
      workflowSlug: "my-workflow",
      featureSlug: "press-outreach",
    });
  });

  it("should parse comma-separated brand IDs", () => {
    const result = extractTrackingHeaders(
      mockRequest({
        "x-brand-id": "brand-1,brand-2,brand-3",
      })
    );

    expect(result).toEqual({ brandIds: ["brand-1", "brand-2", "brand-3"] });
  });

  it("should trim whitespace in CSV brand IDs", () => {
    const result = extractTrackingHeaders(
      mockRequest({
        "x-brand-id": " brand-1 , brand-2 , brand-3 ",
      })
    );

    expect(result).toEqual({ brandIds: ["brand-1", "brand-2", "brand-3"] });
  });

  it("should filter empty entries in CSV brand IDs", () => {
    const result = extractTrackingHeaders(
      mockRequest({
        "x-brand-id": "brand-1,,brand-2,  ,brand-3",
      })
    );

    expect(result).toEqual({ brandIds: ["brand-1", "brand-2", "brand-3"] });
  });
});
