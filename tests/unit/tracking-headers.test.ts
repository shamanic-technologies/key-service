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
        "x-workflow-name": "lead-enrichment",
      })
    );

    expect(result).toEqual({
      campaignId: "camp-123",
      brandId: "brand-456",
      workflowName: "lead-enrichment",
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
        "x-workflow-name": "my-workflow",
      })
    );

    expect(result).toEqual({ brandId: "brand-456", workflowName: "my-workflow" });
  });

  it("should ignore empty string headers", () => {
    const result = extractTrackingHeaders(
      mockRequest({
        "x-campaign-id": "",
        "x-brand-id": "brand-456",
        "x-workflow-name": "",
      })
    );

    expect(result).toEqual({ brandId: "brand-456" });
  });

  it("should ignore whitespace-only headers", () => {
    const result = extractTrackingHeaders(
      mockRequest({
        "x-campaign-id": "  ",
        "x-brand-id": "brand-456",
      })
    );

    expect(result).toEqual({ brandId: "brand-456" });
  });

  it("should return null when all headers are empty", () => {
    const result = extractTrackingHeaders(
      mockRequest({
        "x-campaign-id": "",
        "x-brand-id": "",
        "x-workflow-name": "",
      })
    );

    expect(result).toBeNull();
  });

  it("should trim whitespace from values", () => {
    const result = extractTrackingHeaders(
      mockRequest({
        "x-campaign-id": "  camp-123  ",
        "x-brand-id": "  brand-456  ",
        "x-workflow-name": "  my-workflow  ",
      })
    );

    expect(result).toEqual({
      campaignId: "camp-123",
      brandId: "brand-456",
      workflowName: "my-workflow",
    });
  });
});
