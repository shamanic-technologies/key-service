import { readFileSync } from "fs";
import { resolve } from "path";
import { vi } from "vitest";

/**
 * Regression test: Sentry must be initialized via --import flag BEFORE the
 * module graph is loaded, otherwise Express won't be instrumented in ESM mode.
 *
 * Bug: Importing instrument.ts at the top of index.ts is too late for ESM.
 * The --import flag ensures Sentry loads before any other modules.
 */
describe("Sentry ESM instrumentation", () => {
  const packagePath = resolve(__dirname, "../../package.json");
  const packageJson = JSON.parse(readFileSync(packagePath, "utf-8"));

  it("uses --import flag in start script", () => {
    const startScript = packageJson.scripts?.start || "";
    expect(startScript).toContain("--import");
    expect(startScript).toContain("instrument");
  });

  it("does not have inline Sentry.init() in index.ts", () => {
    const indexPath = resolve(__dirname, "../../src/index.ts");
    const source = readFileSync(indexPath, "utf-8");
    const hasSentryInit = source.includes("Sentry.init(");
    expect(hasSentryInit).toBe(false);
  });

  // @sentry/node 9+ (we run 10) accepts only a boolean for registerEsmLoaderHooks
  // and wraps only the modules it instruments, so drizzle-orm is no longer
  // wrapped and the old `{ exclude: [/drizzle-orm/] }` option is gone.
  it("initializes Sentry with the v10 option shape when SENTRY_DSN is set", async () => {
    vi.resetModules();
    const init = vi.fn();
    const setTag = vi.fn();
    vi.doMock("@sentry/node", () => ({ init, setTag }));
    const prev = process.env.SENTRY_DSN;
    process.env.SENTRY_DSN = "https://public@example.ingest.sentry.io/1";
    try {
      await import("../../src/instrument.js");
    } finally {
      if (prev === undefined) delete process.env.SENTRY_DSN;
      else process.env.SENTRY_DSN = prev;
      vi.doUnmock("@sentry/node");
    }
    expect(init).toHaveBeenCalledTimes(1);
    const opts = init.mock.calls[0][0];
    expect(opts.dsn).toBe("https://public@example.ingest.sentry.io/1");
    expect(opts.registerEsmLoaderHooks === undefined || typeof opts.registerEsmLoaderHooks === "boolean").toBe(true);
    expect(setTag).toHaveBeenCalledWith("service", "key-service");
  });
});
