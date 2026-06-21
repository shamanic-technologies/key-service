import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { traceEvent } from "../../src/lib/trace-event.js";

describe("traceEvent", () => {
  const originalFetch = globalThis.fetch;

  beforeEach(() => {
    vi.stubEnv("RUNS_SERVICE_URL", "https://runs.test");
    vi.stubEnv("RUNS_SERVICE_API_KEY", "test-runs-key");
    globalThis.fetch = vi.fn().mockResolvedValue({ ok: true });
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.unstubAllEnvs();
  });

  it("POSTs to runs-service with correct URL, body, and identity headers", async () => {
    const headers: Record<string, string | string[] | undefined> = {
      "x-org-id": "org-123",
      "x-user-id": "user-456",
      "x-brand-id": "brand-789",
      "x-campaign-id": "camp-abc",
      "x-workflow-slug": "my-workflow",
      "x-feature-slug": "my-feature",
      "x-audience-id": "audience-xyz",
    };

    await traceEvent("run-001", {
      service: "key-service",
      event: "decrypt-key",
      detail: "Decrypting key for provider anthropic",
      level: "info",
      data: { provider: "anthropic" },
    }, headers);

    expect(globalThis.fetch).toHaveBeenCalledOnce();
    const [url, opts] = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(url).toBe("https://runs.test/v1/runs/run-001/events");
    expect(opts.method).toBe("POST");
    expect(JSON.parse(opts.body)).toEqual({
      service: "key-service",
      event: "decrypt-key",
      detail: "Decrypting key for provider anthropic",
      level: "info",
      data: { provider: "anthropic" },
    });
    expect(opts.headers).toMatchObject({
      "Content-Type": "application/json",
      "x-api-key": "test-runs-key",
      "x-org-id": "org-123",
      "x-user-id": "user-456",
      "x-brand-id": "brand-789",
      "x-campaign-id": "camp-abc",
      "x-workflow-slug": "my-workflow",
      "x-feature-slug": "my-feature",
      "x-audience-id": "audience-xyz",
    });
  });

  it("returns without throwing when RUNS_SERVICE_URL is missing", async () => {
    vi.stubEnv("RUNS_SERVICE_URL", "");
    const spy = vi.spyOn(console, "error").mockImplementation(() => {});

    await expect(traceEvent("run-001", {
      service: "key-service",
      event: "test",
    }, {})).resolves.toBeUndefined();

    expect(globalThis.fetch).not.toHaveBeenCalled();
    expect(spy).toHaveBeenCalledWith(
      expect.stringContaining("[key-service]"),
    );
    spy.mockRestore();
  });

  it("returns without throwing when RUNS_SERVICE_API_KEY is missing", async () => {
    vi.stubEnv("RUNS_SERVICE_API_KEY", "");
    const spy = vi.spyOn(console, "error").mockImplementation(() => {});

    await expect(traceEvent("run-001", {
      service: "key-service",
      event: "test",
    }, {})).resolves.toBeUndefined();

    expect(globalThis.fetch).not.toHaveBeenCalled();
    spy.mockRestore();
  });

  it("catches fetch errors without throwing", async () => {
    globalThis.fetch = vi.fn().mockRejectedValue(new Error("network down"));
    const spy = vi.spyOn(console, "error").mockImplementation(() => {});

    await expect(traceEvent("run-001", {
      service: "key-service",
      event: "test",
    }, {})).resolves.toBeUndefined();

    expect(spy).toHaveBeenCalledWith(
      expect.stringContaining("[key-service] Failed to trace event"),
      expect.any(Error),
    );
    spy.mockRestore();
  });

  it("only forwards headers that are present (sparse headers)", async () => {
    await traceEvent("run-001", {
      service: "key-service",
      event: "test",
    }, { "x-org-id": "org-123" });

    const [, opts] = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(opts.headers).toHaveProperty("x-org-id", "org-123");
    expect(opts.headers).not.toHaveProperty("x-user-id");
    expect(opts.headers).not.toHaveProperty("x-brand-id");
    expect(opts.headers).not.toHaveProperty("x-campaign-id");
    expect(opts.headers).not.toHaveProperty("x-workflow-slug");
    expect(opts.headers).not.toHaveProperty("x-feature-slug");
    expect(opts.headers).not.toHaveProperty("x-audience-id");
  });

  it("forwards x-audience-id inbound header to runs-service egress (cost-attribution regression)", async () => {
    await traceEvent("run-001", {
      service: "key-service",
      event: "test",
    }, { "x-audience-id": "audience-xyz" });

    const [, opts] = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(opts.headers).toHaveProperty("x-audience-id", "audience-xyz");
  });
});
