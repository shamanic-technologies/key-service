import { readFileSync } from "fs";
import { resolve } from "path";

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
});
