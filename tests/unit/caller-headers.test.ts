import { describe, it, expect } from "vitest";
import { extractCallerHeaders } from "../../src/lib/caller-headers.js";

function mockRequest(headers: Record<string, string | undefined>) {
  return { headers } as any;
}

describe("extractCallerHeaders", () => {
  it("should return CallerInfo when all headers present", () => {
    const result = extractCallerHeaders(
      mockRequest({
        "x-caller-service": "apollo",
        "x-caller-method": "POST",
        "x-caller-path": "/leads/search",
      })
    );

    expect(result).toEqual({
      service: "apollo",
      method: "POST",
      path: "/leads/search",
    });
  });

  it("should return null when X-Caller-Service missing", () => {
    const result = extractCallerHeaders(
      mockRequest({
        "x-caller-method": "POST",
        "x-caller-path": "/leads/search",
      })
    );

    expect(result).toBeNull();
  });

  it("should return null when X-Caller-Method missing", () => {
    const result = extractCallerHeaders(
      mockRequest({
        "x-caller-service": "apollo",
        "x-caller-path": "/leads/search",
      })
    );

    expect(result).toBeNull();
  });

  it("should return null when X-Caller-Path missing", () => {
    const result = extractCallerHeaders(
      mockRequest({
        "x-caller-service": "apollo",
        "x-caller-method": "POST",
      })
    );

    expect(result).toBeNull();
  });

  it("should return null when headers are empty strings", () => {
    const result = extractCallerHeaders(
      mockRequest({
        "x-caller-service": "",
        "x-caller-method": "POST",
        "x-caller-path": "/leads/search",
      })
    );

    expect(result).toBeNull();
  });

  it("should return null when headers are whitespace only", () => {
    const result = extractCallerHeaders(
      mockRequest({
        "x-caller-service": "  ",
        "x-caller-method": "POST",
        "x-caller-path": "/leads/search",
      })
    );

    expect(result).toBeNull();
  });

  it("should normalize service to lowercase", () => {
    const result = extractCallerHeaders(
      mockRequest({
        "x-caller-service": "Apollo",
        "x-caller-method": "POST",
        "x-caller-path": "/leads/search",
      })
    );

    expect(result?.service).toBe("apollo");
  });

  it("should normalize method to uppercase", () => {
    const result = extractCallerHeaders(
      mockRequest({
        "x-caller-service": "apollo",
        "x-caller-method": "post",
        "x-caller-path": "/leads/search",
      })
    );

    expect(result?.method).toBe("POST");
  });

  it("should trim whitespace from all values", () => {
    const result = extractCallerHeaders(
      mockRequest({
        "x-caller-service": "  apollo  ",
        "x-caller-method": "  POST  ",
        "x-caller-path": "  /leads/search  ",
      })
    );

    expect(result).toEqual({
      service: "apollo",
      method: "POST",
      path: "/leads/search",
    });
  });
});
