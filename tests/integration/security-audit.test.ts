import { describe, it, expect, beforeEach, afterAll, vi } from "vitest";
import request from "supertest";
import { desc, eq } from "drizzle-orm";
import app from "../../src/index.js";
import { db } from "../../src/db/index.js";
import { secretAuditEvents, securityIncidents, knownCallers } from "../../src/db/schema.js";
import { encrypt } from "../../src/lib/crypto.js";
import {
  flushSecurityChecks,
  retryUndeliveredAlerts,
  pruneAuditEvents,
  SWEEP_PER_CALLER,
  SWEEP_PER_SOURCE,
  AUTH_BURST,
} from "../../src/lib/security-alerts.js";
import {
  cleanTestData,
  closeDb,
  insertTestProvider,
  insertTestPlatformKey,
  insertTestOrgKey,
  insertTestBrandKey,
  insertTestOrgProviderKeySource,
} from "../helpers/test-db.js";

const SERVICE_KEY = "test-service-key-security";
const SECRET = "sk-live-SUPER-SECRET-VALUE-1234567890";
const auth = { "x-api-key": SERVICE_KEY };
const caller = (service: string) => ({
  "x-caller-service": service,
  "x-caller-method": "POST",
  "x-caller-path": "/orgs/do-work",
});

const fetchMock = vi.fn(async (_url: string, _init?: RequestInit) => new Response(JSON.stringify({ sent: true }), { status: 200 }));

function alertCalls() {
  return fetchMock.mock.calls
    .filter(([url]) => String(url).endsWith("/platform-staff-alert"))
    .map(([, init]) => JSON.parse(String(init?.body)));
}

async function seedPlatformKey(name: string) {
  const p = await insertTestProvider({ name });
  await insertTestPlatformKey(p.id, { encryptedKey: encrypt(SECRET) });
  return p;
}

async function known(service: string) {
  await db.insert(knownCallers).values({ service });
}

async function audits() {
  await flushSecurityChecks();
  return db.select().from(secretAuditEvents).orderBy(desc(secretAuditEvents.createdAt));
}

async function incidents() {
  await flushSecurityChecks();
  return db.select().from(securityIncidents);
}

describe("secret audit + security alerts (SECURITY-ALERTS-1128)", () => {
  beforeEach(async () => {
    await cleanTestData();
    process.env.KEY_SERVICE_API_KEY = SERVICE_KEY;
    process.env.TRANSACTIONAL_EMAIL_SERVICE_URL = "http://tes.test";
    process.env.TRANSACTIONAL_EMAIL_SERVICE_API_KEY = "tes-key";
    fetchMock.mockClear();
    fetchMock.mockImplementation(async () => new Response(JSON.stringify({ sent: true }), { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);
  });

  afterAll(async () => {
    await cleanTestData();
    vi.unstubAllGlobals();
    await closeDb();
  });

  describe("audit rows", () => {
    it("a platform decrypt leaves one row: provider, caller, source, outcome, never the key", async () => {
      await seedPlatformKey("anthropic");
      await known("chat-service");
      const res = await request(app).get("/keys/platform/anthropic/decrypt").set(auth).set(caller("chat-service")).set("x-forwarded-for", "203.0.113.9");
      expect(res.status).toBe(200);
      expect(res.body.key).toBe(SECRET);

      const rows = await audits();
      expect(rows).toHaveLength(1);
      expect(rows[0]).toMatchObject({
        action: "decrypt",
        grain: "platform",
        provider: "anthropic",
        callerService: "chat-service",
        callerMethod: "POST",
        callerPath: "/orgs/do-work",
        requestMethod: "GET",
        requestPath: "/keys/platform/anthropic/decrypt",
        sourceIp: "127.0.0.1",
        forwardedFor: "203.0.113.9",
        outcome: "success",
      });
      expect(JSON.stringify(rows)).not.toContain(SECRET);
      expect(JSON.stringify(rows)).not.toContain(SERVICE_KEY);
    });

    it("a decrypt of an unknown provider is recorded not_found; one without caller headers is recorded refused", async () => {
      await known("chat-service");
      await request(app).get("/keys/platform/nope/decrypt").set(auth).set(caller("chat-service")).expect(404);
      await request(app).get("/keys/platform/nope/decrypt").set(auth).expect(400);
      const outcomes = (await audits()).map((r) => r.outcome).sort();
      expect(outcomes).toEqual(["not_found", "refused"]);
    });

    it("org-grain and brand-grain decrypts are recorded with their org / brand", async () => {
      const p = await insertTestProvider({ name: "instantly" });
      await insertTestOrgKey(p.id, { orgId: "org-1", encryptedKey: encrypt(SECRET) });
      await insertTestOrgProviderKeySource({ orgId: "org-1", providerId: p.id, keySource: "org" });
      await insertTestBrandKey(p.id, { orgId: "org-1", brandId: "brand-1", encryptedKey: encrypt(SECRET) });
      await known("instantly-service");
      const id = { "x-org-id": "org-1", "x-user-id": "user-1" };
      await request(app).get("/keys/instantly/decrypt").set(auth).set(id).set(caller("instantly-service")).expect(200);
      await request(app).get("/keys/brands/brand-1/instantly/decrypt").set(auth).set(id).set(caller("instantly-service")).expect(200);
      const rows = await audits();
      expect(rows.map((r) => [r.grain, r.orgId, r.brandId]).sort()).toEqual([
        ["brand", "org-1", "brand-1"],
        ["org", "org-1", null],
      ]);
      expect(JSON.stringify(rows)).not.toContain(SECRET);
    });

    it("a wrong service key is recorded auth_rejected and still answers 401", async () => {
      const res = await request(app).get("/keys/platform/anthropic/decrypt").set("x-api-key", "wrong-key-abcdef");
      expect(res.status).toBe(401);
      const rows = await audits();
      expect(rows).toHaveLength(1);
      expect(rows[0]).toMatchObject({ action: "auth_rejected", outcome: "refused", requestPath: "/keys/platform/anthropic/decrypt" });
      expect(JSON.stringify(rows)).not.toContain("wrong-key-abcdef");
    });

    it("the auth REJECTED log line prints no character of either key", async () => {
      const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
      await request(app).get("/keys/platform/anthropic/decrypt").set("x-api-key", "zzzzWRONG");
      const lines = warn.mock.calls.map((c) => c.join(" ")).filter((l) => l.includes("auth REJECTED"));
      warn.mockRestore();
      expect(lines).toHaveLength(1);
      expect(lines[0]).not.toContain(SERVICE_KEY.slice(0, 4));
      expect(lines[0]).not.toContain("zzzz");
    });
  });

  describe("key writes", () => {
    it("creating a platform key opens one key_write incident and mails staff once", async () => {
      await request(app).post("/platform-keys").set(auth).send({ provider: "probe26210", apiKey: SECRET }).expect(200);
      const inc = await incidents();
      expect(inc).toHaveLength(1);
      expect(inc[0].kind).toBe("key_write");
      const calls = alertCalls();
      expect(calls).toHaveLength(1);
      expect(calls[0]).toMatchObject({ eventType: "security_alert", eventId: `key-service:key_write:${inc[0].id}` });
      expect(calls[0].metadata.kind).toBe("key_write");
      expect(calls[0].metadata.summary).toContain("probe26210");
      expect(calls[0].metadata.evidence.length).toBeGreaterThan(0);
      expect(JSON.stringify(calls)).not.toContain(SECRET);
    });

    it("a boot-time registration re-sending the SAME value writes nothing and alerts nothing", async () => {
      await seedPlatformKey("anthropic");
      await request(app).post("/platform-keys").set(auth).send({ provider: "anthropic", apiKey: SECRET }).expect(200);
      expect(await audits()).toHaveLength(0);
      expect(alertCalls()).toHaveLength(0);
    });

    it("a burst of writes from one caller is ONE incident (one email), counted", async () => {
      for (let i = 0; i < 3; i++) {
        await request(app).post("/platform-keys").set(auth).send({ provider: `p${i}`, apiKey: `${SECRET}${i}` }).expect(200);
      }
      const inc = await incidents();
      expect(inc).toHaveLength(1);
      expect(inc[0].eventCount).toBe(3);
      expect(alertCalls()).toHaveLength(1);
    });

    it("org key create and delete are audited", async () => {
      const id = { "x-org-id": "org-9", "x-user-id": "user-9" };
      await request(app).post("/keys").set(auth).set(id).send({ provider: "openai", apiKey: SECRET }).expect(200);
      await request(app).delete("/keys/openai").set(auth).set(id).expect(200);
      const rows = await audits();
      expect(rows.map((r) => `${r.action}:${r.grain}:${r.orgId}`).sort()).toEqual(["create:org:org-9", "delete:org:org-9"]);
    });
  });

  describe("unknown caller", () => {
    it("a decrypt from a caller never seen in 30 days mails staff once", async () => {
      await seedPlatformKey("anthropic");
      await request(app).get("/keys/platform/anthropic/decrypt").set(auth).set(caller("probe26235")).expect(200);
      await request(app).get("/keys/platform/anthropic/decrypt").set(auth).set(caller("probe26235")).expect(200);
      const inc = await incidents();
      expect(inc.map((i) => [i.kind, i.subject])).toEqual([["unknown_caller_decrypt", "probe26235"]]);
      const calls = alertCalls();
      expect(calls).toHaveLength(1);
      expect(calls[0].metadata.summary).toContain("probe26235");
    });

    it("a caller seen in the last 30 days raises nothing", async () => {
      await seedPlatformKey("anthropic");
      await known("chat-service");
      await request(app).get("/keys/platform/anthropic/decrypt").set(auth).set(caller("chat-service")).expect(200);
      expect(await incidents()).toHaveLength(0);
    });

    it("a caller last seen 31 days ago counts as unknown", async () => {
      await seedPlatformKey("anthropic");
      await db.insert(knownCallers).values({ service: "billing-service", lastSeenAt: new Date(Date.now() - 31 * 86_400_000) });
      await request(app).get("/keys/platform/anthropic/decrypt").set(auth).set(caller("billing-service")).expect(200);
      expect((await incidents()).map((i) => i.kind)).toEqual(["unknown_caller_decrypt"]);
    });
  });

  describe("our own box jobs (SECURITY-OWN-ACTORS-1128)", () => {
    const R2 = [
      "cloudflare-r2-access-key-id",
      "cloudflare-r2-secret-access-key",
      "cloudflare-r2-account-id",
      "cloudflare-r2-private-bucket-name",
      "cloudflare-r2-bucket-name",
    ];
    const box = (service: string, path: string) => ({ "x-caller-service": service, "x-caller-method": "GET", "x-caller-path": path });

    it("replaying 2026-11-27's first runs of security-watch and security-ship mails nothing and stays green", async () => {
      for (const p of ["anthropic", "postmark", "stripe", ...R2]) await seedPlatformKey(p);
      for (const p of ["anthropic", "postmark", "stripe"]) {
        await request(app).get(`/keys/platform/${p}/decrypt`).set(auth).set(box("security-watch", "/box/security-watch/vendor-keys")).expect(200);
      }
      for (const p of R2) {
        await request(app).get(`/keys/platform/${p}/decrypt`).set(auth).set(box("security-ship", "/box/security-ship")).expect(200);
      }
      expect(await incidents()).toHaveLength(0);
      expect(alertCalls()).toHaveLength(0);
      expect((await audits()).length).toBe(8); // still audited, every read
      const res = await request(app).get("/internal/security/daily?days=1").set(auth).expect(200);
      expect(res.body.red).toBe(false);
    });

    it("our job stays us after 31 idle days", async () => {
      await seedPlatformKey("stripe");
      await db.insert(knownCallers).values({ service: "security-watch", lastSeenAt: new Date(Date.now() - 31 * 86_400_000) });
      await request(app).get("/keys/platform/stripe/decrypt").set(auth).set(box("security-watch", "/box/security-watch/vendor-keys")).expect(200);
      expect(await incidents()).toHaveLength(0);
      expect(alertCalls()).toHaveLength(0);
    });

    it("the same read by an unknown caller name still mails staff", async () => {
      await seedPlatformKey("anthropic");
      await request(app).get("/keys/platform/anthropic/decrypt").set(auth).set(box("security-watch-2", "/box/x")).expect(200);
      expect((await incidents()).map((i) => [i.kind, i.subject])).toEqual([["unknown_caller_decrypt", "security-watch-2"]]);
      expect(alertCalls()).toHaveLength(1);
    });

    it("our job's name reading a key that job never reads still mails staff, even once the name is known", async () => {
      await seedPlatformKey("openai");
      await known("security-watch");
      await request(app).get("/keys/platform/openai/decrypt").set(auth).set(box("security-watch", "/box/security-watch/vendor-keys")).expect(200);
      const inc = await incidents();
      expect(inc.map((i) => [i.kind, i.subject])).toEqual([["unknown_caller_decrypt", "security-watch:off-list:openai"]]);
      const calls = alertCalls();
      expect(calls).toHaveLength(1);
      expect(calls[0].metadata.summary).toContain("never reads");
      const res = await request(app).get("/internal/security/daily?days=1").set(auth).expect(200);
      expect(res.body.red).toBe(true);
      expect(res.body.incidents[0].ourOwn).toBe(false);
    });

    it("an org key read under our job's name still mails staff", async () => {
      const p = await insertTestProvider({ name: "stripe" });
      await insertTestOrgKey(p.id, { orgId: "org-1", encryptedKey: encrypt(SECRET) });
      await insertTestOrgProviderKeySource({ orgId: "org-1", providerId: p.id, keySource: "org" });
      await request(app)
        .get("/keys/stripe/decrypt")
        .set(auth)
        .set({ "x-org-id": "org-1", "x-user-id": "user-1" })
        .set(box("security-watch", "/box/x"));
      expect((await incidents()).map((i) => i.subject)).toEqual(["security-watch:off-list:stripe"]);
    });

    it("2026-11-27's incidents on our jobs' bare names are listed as ours and never turn Monitoring red", async () => {
      await db.insert(securityIncidents).values([
        { kind: "unknown_caller_decrypt", subject: "security-ship", summary: "Unknown caller 'security-ship' read platform key 'cloudflare-r2-access-key-id'", evidence: "-", alertStatus: "sent" },
        { kind: "unknown_caller_decrypt", subject: "security-watch", summary: "Unknown caller 'security-watch' read platform key 'anthropic'", evidence: "-", alertStatus: "sent" },
      ]);
      const res = await request(app).get("/internal/security/daily?days=1").set(auth).expect(200);
      expect(res.body.red).toBe(false);
      expect(res.body.incidentsLast24h).toBe(0);
      expect(res.body.days[0].incidentsOpened).toBe(0);
      expect(res.body.incidents.map((i: { ourOwn: boolean }) => i.ourOwn)).toEqual([true, true]);
    });
  });

  describe("provider sweep", () => {
    it(`> ${SWEEP_PER_CALLER} distinct providers from one caller in 10 min is ONE incident`, async () => {
      await known("auto-collect");
      for (let i = 0; i <= SWEEP_PER_CALLER + 2; i++) {
        await seedPlatformKey(`prov-${i}`);
        await request(app).get(`/keys/platform/prov-${i}/decrypt`).set(auth).set(caller("auto-collect")).expect(200);
      }
      const inc = (await incidents()).filter((i) => i.kind === "provider_sweep");
      expect(inc).toHaveLength(1);
      expect(inc[0].subject).toBe("caller:auto-collect");
      expect(alertCalls().filter((c) => c.metadata.kind === "provider_sweep")).toHaveLength(1);
    });

    it(`exactly ${SWEEP_PER_CALLER} distinct providers raises nothing`, async () => {
      await known("chat-service");
      for (let i = 0; i < SWEEP_PER_CALLER; i++) {
        await seedPlatformKey(`prov-${i}`);
        await request(app).get(`/keys/platform/prov-${i}/decrypt`).set(auth).set(caller("chat-service")).expect(200);
      }
      expect(await incidents()).toHaveLength(0);
    });
  });

  describe("our backup's bulk read (BACKUP-SWEEP-ALERT-1128)", () => {
    const DSNS = Array.from({ length: 37 }, (_, i) => `pg-backup-dsn-db${i}_service`);
    const R2 = ["cloudflare-r2-access-key-id", "cloudflare-r2-secret-access-key", "cloudflare-r2-account-id", "cloudflare-r2-private-bucket-name"];
    const job = { "x-caller-service": "pg-backup", "x-caller-method": "CRON", "x-caller-path": "/jobs/pg-backup" };

    async function replayBackup() {
      for (const p of [...DSNS, ...R2]) await seedPlatformKey(p);
      for (const p of [...DSNS, ...R2]) await request(app).get(`/keys/platform/${p}/decrypt`).set(auth).set(job).expect(200);
    }

    // 2026-11-28 15:00 the source address read 41 distinct secrets: 37 DSNs + 4 R2 keys reproduce it.
    it("replaying 2026-11-28 15:00 (every DSN + the R2 keys) raises no sweep, per caller or per source, and mails nothing", async () => {
      expect(DSNS.length + R2.length).toBeGreaterThan(SWEEP_PER_SOURCE);
      await replayBackup();
      expect(await incidents()).toHaveLength(0);
      expect(alertCalls()).toHaveLength(0);
      expect((await audits()).length).toBe(DSNS.length + R2.length); // still audited, every read
    });

    it("the same caller reading one off-list key still raises", async () => {
      await replayBackup();
      await seedPlatformKey("anthropic");
      await request(app).get("/keys/platform/anthropic/decrypt").set(auth).set(job).expect(200);
      expect((await incidents()).map((i) => [i.kind, i.subject])).toEqual([["unknown_caller_decrypt", "pg-backup:off-list:anthropic"]]);
      expect(alertCalls()).toHaveLength(1);
    });

    it("off-list reads by our job's name count toward the sweep", async () => {
      for (let i = 0; i <= SWEEP_PER_CALLER; i++) {
        await seedPlatformKey(`prov-${i}`);
        await request(app).get(`/keys/platform/prov-${i}/decrypt`).set(auth).set(job).expect(200);
      }
      expect((await incidents()).filter((i) => i.kind === "provider_sweep").map((i) => i.subject)).toEqual(["caller:pg-backup"]);
    });

    it("a different caller reading the same DSNs still raises both sweeps", async () => {
      await known("cloudflare-storage");
      for (const p of [...DSNS, ...R2]) await seedPlatformKey(p);
      for (const p of [...DSNS, ...R2]) await request(app).get(`/keys/platform/${p}/decrypt`).set(auth).set(caller("cloudflare-storage")).expect(200);
      const subjects = (await incidents()).filter((i) => i.kind === "provider_sweep").map((i) => i.subject.split(":")[0]).sort();
      expect(subjects).toEqual(["caller", "source"]);
      expect(alertCalls().filter((c) => c.metadata.kind === "provider_sweep")).toHaveLength(2);
    });

    it("a bare prefix with no database name is not ours", async () => {
      await seedPlatformKey("pg-backup-dsn-");
      await request(app).get("/keys/platform/pg-backup-dsn-/decrypt").set(auth).set(job).expect(200);
      expect((await incidents()).map((i) => i.subject)).toEqual(["pg-backup:off-list:pg-backup-dsn-"]);
    });
  });

  describe("wrong-key burst", () => {
    it(`${AUTH_BURST} wrong-key requests from one source in 10 min is ONE incident`, async () => {
      for (let i = 0; i < AUTH_BURST + 3; i++) {
        await request(app).get("/keys/platform/x/decrypt").set("x-api-key", `guess-${i}`).expect(401);
      }
      const inc = await incidents();
      expect(inc.map((i) => i.kind)).toEqual(["auth_failure_burst"]);
      expect(alertCalls()).toHaveLength(1);
    });

    it(`${AUTH_BURST - 1} wrong-key requests raise nothing`, async () => {
      for (let i = 0; i < AUTH_BURST - 1; i++) {
        await request(app).get("/keys/platform/x/decrypt").set("x-api-key", `guess-${i}`).expect(401);
      }
      expect(await incidents()).toHaveLength(0);
    });
  });

  describe("delivery", () => {
    it("an undelivered alert stays failed and the retry sweep resends it under the SAME eventId", async () => {
      fetchMock.mockImplementation(async () => new Response("down", { status: 502 }));
      await seedPlatformKey("anthropic");
      await request(app).get("/keys/platform/anthropic/decrypt").set(auth).set(caller("stranger")).expect(200);
      let [inc] = await incidents();
      expect(inc.alertStatus).toBe("failed");
      const firstEventId = alertCalls()[0].eventId;

      fetchMock.mockImplementation(async () => new Response(JSON.stringify({ sent: true }), { status: 200 }));
      expect(await retryUndeliveredAlerts()).toBe(1);
      [inc] = await db.select().from(securityIncidents).where(eq(securityIncidents.id, inc.id));
      expect(inc.alertStatus).toBe("sent");
      const ids = alertCalls().map((c) => c.eventId);
      expect(ids).toEqual([firstEventId, firstEventId]);
      expect(await retryUndeliveredAlerts()).toBe(0);
    });

    it("the decrypt still answers when the alert cannot be sent", async () => {
      fetchMock.mockImplementation(async () => { throw new Error("ECONNREFUSED"); });
      await seedPlatformKey("anthropic");
      const res = await request(app).get("/keys/platform/anthropic/decrypt").set(auth).set(caller("stranger"));
      expect(res.status).toBe(200);
      expect((await incidents())[0].alertStatus).toBe("failed");
    });
  });

  describe("staff proof-of-fire", () => {
    it("the box-only test token marks the alert [TEST] (test: \"true\") and keeps Monitoring green", async () => {
      process.env.SECURITY_ALERT_TEST_TOKEN = "tok-123456";
      await seedPlatformKey("anthropic");
      await request(app).get("/keys/platform/anthropic/decrypt").set(auth).set(caller("synthetic-test")).set("x-security-alert-test", "tok-123456").expect(200);
      await flushSecurityChecks();
      const calls = alertCalls();
      expect(calls).toHaveLength(1);
      expect(calls[0].metadata.test).toBe("true");
      expect(calls[0].metadata.firstSeenAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);
      const res = await request(app).get("/internal/security/daily?days=1").set(auth).expect(200);
      expect(res.body.red).toBe(false);
      expect(res.body.incidents[0].test).toBe(true);
      delete process.env.SECURITY_ALERT_TEST_TOKEN;
    });

    it("a wrong or absent token is a REAL alert (a caller cannot dress a dump up as a test)", async () => {
      process.env.SECURITY_ALERT_TEST_TOKEN = "tok-123456";
      await seedPlatformKey("anthropic");
      await request(app).get("/keys/platform/anthropic/decrypt").set(auth).set(caller("synthetic-test")).set("x-security-alert-test", "tok-000000").expect(200);
      await flushSecurityChecks();
      const calls = alertCalls();
      expect(calls).toHaveLength(1);
      expect(calls[0].metadata.test).toBeUndefined();
      delete process.env.SECURITY_ALERT_TEST_TOKEN;
    });
  });

  describe("monitoring series + retention", () => {
    it("GET /internal/security/daily serves a zero-filled daily series, red while an incident is fresh", async () => {
      await seedPlatformKey("anthropic");
      await known("chat-service");
      await request(app).get("/keys/platform/anthropic/decrypt").set(auth).set(caller("chat-service")).expect(200);
      let res = await request(app).get("/internal/security/daily?days=7").set(auth).expect(200);
      expect(res.body.days).toHaveLength(7);
      expect(res.body.days[6]).toMatchObject({ secretReads: 1, keyWrites: 0, wrongKeyRequests: 0, incidentsOpened: 0 });
      expect(res.body.red).toBe(false);

      await request(app).get("/keys/platform/anthropic/decrypt").set(auth).set(caller("stranger")).expect(200);
      await flushSecurityChecks();
      res = await request(app).get("/internal/security/daily?days=7").set(auth).expect(200);
      expect(res.body.red).toBe(true);
      expect(res.body.days[6].incidentsOpened).toBe(1);
      expect(res.body.incidents[0].kind).toBe("unknown_caller_decrypt");
    });

    it("the retention sweep deletes rows older than 90 days only", async () => {
      const base = { action: "decrypt", requestMethod: "GET", requestPath: "/x", sourceIp: "10.0.0.1", outcome: "success" };
      await db.insert(secretAuditEvents).values([
        { ...base, createdAt: new Date(Date.now() - 91 * 86_400_000) },
        { ...base, createdAt: new Date(Date.now() - 89 * 86_400_000) },
      ]);
      expect(await pruneAuditEvents()).toBe(1);
      expect(await db.select().from(secretAuditEvents)).toHaveLength(1);
    });
  });

  // SECURITY-ALERTS-OURS-1128: transactional-email-service decides whether an alert was caused by us.
  // key-service hands the source address and stores the answer: an incident judged ours is listed, never red.
  describe("origin + ours (SECURITY-ALERTS-OURS-1128)", () => {
    it("the alert carries originIp; an answer `ours` is stored and the incident never turns red", async () => {
      fetchMock.mockImplementation(async () =>
        new Response(JSON.stringify({ sent: false, duplicate: false, ours: "from inside our server (172.18.0.5), relaying nobody, while one of us was logged in over SSH" }), { status: 200 }),
      );
      await seedPlatformKey("anthropic");
      await request(app).get("/keys/platform/anthropic/decrypt").set(auth).set(caller("secrets-rotate-1127")).expect(200);
      const [inc] = await incidents();
      expect(inc.kind).toBe("unknown_caller_decrypt");
      expect(inc.originIp).toBeTruthy();
      expect(inc.alertStatus).toBe("sent");
      expect(inc.oursReason).toMatch(/from inside our server/);
      expect(alertCalls()[0].metadata.originIp).toBe(inc.originIp);

      const res = await request(app).get("/internal/security/daily?days=1").set(auth).expect(200);
      expect(res.body.red).toBe(false);
      expect(res.body.days[0].incidentsOpened).toBe(0);
      expect(res.body.incidents[0]).toMatchObject({ ourOwn: true, oursReason: expect.stringMatching(/inside our server/) });
    });

    it("an answer without `ours` (emailed) stays red", async () => {
      fetchMock.mockImplementation(async () => new Response(JSON.stringify({ sent: true, duplicate: false }), { status: 200 }));
      await seedPlatformKey("anthropic");
      await request(app).get("/keys/platform/anthropic/decrypt").set(auth).set(caller("probe26235")).expect(200);
      const [inc] = await incidents();
      expect(inc.oursReason).toBeNull();
      const res = await request(app).get("/internal/security/daily?days=1").set(auth).expect(200);
      expect(res.body.red).toBe(true);
    });
  });
});
