import { describe, it, expect, beforeEach, afterAll } from "vitest";
import request from "supertest";
import express from "express";
import brandKeysRoutes from "../../src/routes/brand-keys.js";
import keysRoutes from "../../src/routes/keys.js";
import platformKeysRoutes from "../../src/routes/platform-keys.js";
import { requireIdentityHeaders } from "../../src/middleware/auth.js";
import { cleanTestData, closeDb } from "../helpers/test-db.js";

const app = express();
app.use(express.json());
// Mount order mirrors src/index.ts: the brand grain owns /keys/brands/*, the
// org grain keeps everything else under /keys.
app.use("/keys/brands", requireIdentityHeaders, brandKeysRoutes);
app.use("/keys", requireIdentityHeaders, keysRoutes);
app.use("/platform-keys", platformKeysRoutes);

const ORG = "org-agency-1";
const OTHER_ORG = "org-agency-2";
const BRAND_A = "brand-aaaa-1111";
const BRAND_B = "brand-bbbb-2222";

const identity = { "x-org-id": ORG, "x-user-id": "user-1" };
const otherOrgIdentity = { "x-org-id": OTHER_ORG, "x-user-id": "user-2" };
const caller = {
  "x-caller-service": "crm-service",
  "x-caller-method": "POST",
  "x-caller-path": "/orgs/crm/contacts",
};

describe("/keys/brands — brand-scoped third-party credentials", () => {
  beforeEach(async () => {
    await cleanTestData();
  });

  afterAll(async () => {
    await cleanTestData();
    await closeDb();
  });

  // ==================== IDENTITY ====================

  describe("identity headers enforcement", () => {
    it("rejects a brand-scoped read without x-org-id", async () => {
      const res = await request(app)
        .get(`/keys/brands/${BRAND_A}/gohighlevel/decrypt`)
        .set({ ...caller, "x-user-id": "user-1" });

      expect(res.status).toBe(400);
      expect(res.body.error).toContain("x-org-id");
    });

    it("rejects a brand-scoped write without x-user-id", async () => {
      const res = await request(app)
        .post(`/keys/brands/${BRAND_A}`)
        .set({ "x-org-id": ORG })
        .send({ provider: "gohighlevel", apiKey: "ghl-secret" });

      expect(res.status).toBe(400);
      expect(res.body.error).toContain("x-user-id");
    });
  });

  // ==================== AC1: COEXISTENCE ====================

  describe("AC1 — two brands of one org, same provider, different credentials", () => {
    it("stores and resolves each brand's own credential", async () => {
      await request(app)
        .post(`/keys/brands/${BRAND_A}`)
        .set(identity)
        .send({ provider: "gohighlevel", apiKey: "ghl-brand-a-secret" })
        .expect(200);

      await request(app)
        .post(`/keys/brands/${BRAND_B}`)
        .set(identity)
        .send({ provider: "gohighlevel", apiKey: "ghl-brand-b-secret" })
        .expect(200);

      const a = await request(app)
        .get(`/keys/brands/${BRAND_A}/gohighlevel/decrypt`)
        .set({ ...identity, ...caller });
      const b = await request(app)
        .get(`/keys/brands/${BRAND_B}/gohighlevel/decrypt`)
        .set({ ...identity, ...caller });

      expect(a.status).toBe(200);
      expect(b.status).toBe(200);
      expect(a.body.key).toBe("ghl-brand-a-secret");
      expect(b.body.key).toBe("ghl-brand-b-secret");
      expect(a.body.brandId).toBe(BRAND_A);
      expect(b.body.brandId).toBe(BRAND_B);
      expect(a.body.keySource).toBe("brand");
    });

    it("storing brand B's credential does not overwrite brand A's", async () => {
      await request(app)
        .post(`/keys/brands/${BRAND_A}`)
        .set(identity)
        .send({ provider: "gohighlevel", apiKey: "ghl-brand-a-secret" })
        .expect(200);

      await request(app)
        .post(`/keys/brands/${BRAND_B}`)
        .set(identity)
        .send({ provider: "gohighlevel", apiKey: "ghl-brand-b-secret" })
        .expect(200);

      const a = await request(app)
        .get(`/keys/brands/${BRAND_A}/gohighlevel/decrypt`)
        .set({ ...identity, ...caller });

      expect(a.body.key).toBe("ghl-brand-a-secret");
    });

    it("re-storing the same brand+provider updates in place, it does not duplicate", async () => {
      await request(app)
        .post(`/keys/brands/${BRAND_A}`)
        .set(identity)
        .send({ provider: "gohighlevel", apiKey: "ghl-first" })
        .expect(200);

      await request(app)
        .post(`/keys/brands/${BRAND_A}`)
        .set(identity)
        .send({ provider: "gohighlevel", apiKey: "ghl-second" })
        .expect(200);

      const list = await request(app).get(`/keys/brands/${BRAND_A}`).set(identity);
      expect(list.status).toBe(200);
      expect(list.body.keys).toHaveLength(1);

      const decrypted = await request(app)
        .get(`/keys/brands/${BRAND_A}/gohighlevel/decrypt`)
        .set({ ...identity, ...caller });
      expect(decrypted.body.key).toBe("ghl-second");
    });

    it("lists only the requested brand's keys", async () => {
      await request(app)
        .post(`/keys/brands/${BRAND_A}`)
        .set(identity)
        .send({ provider: "gohighlevel", apiKey: "ghl-brand-a-secret" });
      await request(app)
        .post(`/keys/brands/${BRAND_B}`)
        .set(identity)
        .send({ provider: "gohighlevel", apiKey: "ghl-brand-b-secret" });

      const res = await request(app).get(`/keys/brands/${BRAND_A}`).set(identity);

      expect(res.body.brandId).toBe(BRAND_A);
      expect(res.body.keys).toHaveLength(1);
      expect(res.body.keys[0].provider).toBe("gohighlevel");
    });
  });

  // ==================== AC3: FAIL LOUD, NO SUBSTITUTION ====================

  describe("AC3 — an unset brand credential is reported absent, never substituted", () => {
    it("404s for a brand that has no credential, even when the org has one", async () => {
      await request(app)
        .post("/keys")
        .set(identity)
        .send({ provider: "gohighlevel", apiKey: "ghl-org-wide-secret" })
        .expect(200);

      const res = await request(app)
        .get(`/keys/brands/${BRAND_A}/gohighlevel/decrypt`)
        .set({ ...identity, ...caller });

      expect(res.status).toBe(404);
      expect(res.body.key).toBeUndefined();
      expect(res.body.error).toContain(BRAND_A);
    });

    it("404s for a brand that has no credential, even when a SIBLING brand has one", async () => {
      await request(app)
        .post(`/keys/brands/${BRAND_B}`)
        .set(identity)
        .send({ provider: "gohighlevel", apiKey: "ghl-brand-b-secret" })
        .expect(200);

      const res = await request(app)
        .get(`/keys/brands/${BRAND_A}/gohighlevel/decrypt`)
        .set({ ...identity, ...caller });

      expect(res.status).toBe(404);
      expect(res.body.key).toBeUndefined();
    });

    it("404s when the provider itself was never registered", async () => {
      const res = await request(app)
        .get(`/keys/brands/${BRAND_A}/never-seen-provider/decrypt`)
        .set({ ...identity, ...caller });

      expect(res.status).toBe(404);
      expect(res.body.key).toBeUndefined();
    });

    it("does not serve one org's brand credential to another org", async () => {
      await request(app)
        .post(`/keys/brands/${BRAND_A}`)
        .set(identity)
        .send({ provider: "gohighlevel", apiKey: "ghl-brand-a-secret" })
        .expect(200);

      const res = await request(app)
        .get(`/keys/brands/${BRAND_A}/gohighlevel/decrypt`)
        .set({ ...otherOrgIdentity, ...caller });

      expect(res.status).toBe(404);
      expect(res.body.key).toBeUndefined();
    });

    it("rejects a decrypt without caller headers", async () => {
      await request(app)
        .post(`/keys/brands/${BRAND_A}`)
        .set(identity)
        .send({ provider: "gohighlevel", apiKey: "ghl-brand-a-secret" });

      const res = await request(app)
        .get(`/keys/brands/${BRAND_A}/gohighlevel/decrypt`)
        .set(identity);

      expect(res.status).toBe(400);
      expect(res.body.key).toBeUndefined();
    });

    it("rejects a write with a missing apiKey instead of storing an empty credential", async () => {
      const res = await request(app)
        .post(`/keys/brands/${BRAND_A}`)
        .set(identity)
        .send({ provider: "gohighlevel" });

      expect(res.status).toBe(400);
    });
  });

  // ==================== AC4: MASKED READ ====================

  describe("AC4 — the masked read never exposes a usable credential", () => {
    it("returns a mask, not the credential, on both write and list", async () => {
      const secret = "ghl-pit-0123456789abcdef";

      const write = await request(app)
        .post(`/keys/brands/${BRAND_A}`)
        .set(identity)
        .send({ provider: "gohighlevel", apiKey: secret });

      expect(write.status).toBe(200);
      expect(write.body.maskedKey).not.toBe(secret);
      expect(write.body.maskedKey).toBe("ghl-...cdef");
      expect(JSON.stringify(write.body)).not.toContain(secret);

      const list = await request(app).get(`/keys/brands/${BRAND_A}`).set(identity);
      expect(list.body.keys[0].maskedKey).toBe("ghl-...cdef");
      expect(JSON.stringify(list.body)).not.toContain(secret);
    });

    it("masks a short credential entirely", async () => {
      await request(app)
        .post(`/keys/brands/${BRAND_A}`)
        .set(identity)
        .send({ provider: "gohighlevel", apiKey: "short" })
        .expect(200);

      const list = await request(app).get(`/keys/brands/${BRAND_A}`).set(identity);
      expect(list.body.keys[0].maskedKey).toBe("••••••••");
      expect(JSON.stringify(list.body)).not.toContain("short");
    });
  });

  // ==================== DELETE ====================

  describe("DELETE /keys/brands/:brandId/:provider", () => {
    it("deletes only that brand's credential", async () => {
      await request(app)
        .post(`/keys/brands/${BRAND_A}`)
        .set(identity)
        .send({ provider: "gohighlevel", apiKey: "ghl-brand-a-secret" });
      await request(app)
        .post(`/keys/brands/${BRAND_B}`)
        .set(identity)
        .send({ provider: "gohighlevel", apiKey: "ghl-brand-b-secret" });

      await request(app)
        .delete(`/keys/brands/${BRAND_A}/gohighlevel`)
        .set(identity)
        .expect(200);

      const a = await request(app)
        .get(`/keys/brands/${BRAND_A}/gohighlevel/decrypt`)
        .set({ ...identity, ...caller });
      const b = await request(app)
        .get(`/keys/brands/${BRAND_B}/gohighlevel/decrypt`)
        .set({ ...identity, ...caller });

      expect(a.status).toBe(404);
      expect(b.status).toBe(200);
      expect(b.body.key).toBe("ghl-brand-b-secret");
    });

    it("is idempotent when nothing is stored", async () => {
      const res = await request(app)
        .delete(`/keys/brands/${BRAND_A}/gohighlevel`)
        .set(identity);

      expect(res.status).toBe(200);
    });
  });

  // ==================== AC2: NO REGRESSION ON THE ORG GRAIN ====================

  describe("AC2 — the org grain behaves exactly as before", () => {
    it("an org key set before any brand key still resolves to itself", async () => {
      await request(app)
        .post("/keys")
        .set(identity)
        .send({ provider: "gohighlevel", apiKey: "ghl-org-wide-secret" })
        .expect(200);
      await request(app)
        .put("/keys/gohighlevel/source")
        .set(identity)
        .send({ keySource: "org" })
        .expect(200);

      // Brand credentials land for two brands of the same org.
      await request(app)
        .post(`/keys/brands/${BRAND_A}`)
        .set(identity)
        .send({ provider: "gohighlevel", apiKey: "ghl-brand-a-secret" });
      await request(app)
        .post(`/keys/brands/${BRAND_B}`)
        .set(identity)
        .send({ provider: "gohighlevel", apiKey: "ghl-brand-b-secret" });

      const org = await request(app)
        .get("/keys/gohighlevel/decrypt")
        .set({ ...identity, ...caller });

      expect(org.status).toBe(200);
      expect(org.body.key).toBe("ghl-org-wide-secret");
      expect(org.body.keySource).toBe("org");
    });

    it("the org key list does not show brand keys", async () => {
      await request(app)
        .post("/keys")
        .set(identity)
        .send({ provider: "gohighlevel", apiKey: "ghl-org-wide-secret" });
      await request(app)
        .post(`/keys/brands/${BRAND_A}`)
        .set(identity)
        .send({ provider: "hubspot", apiKey: "hub-brand-a-secret" });

      const res = await request(app).get("/keys").set(identity);

      expect(res.body.keys).toHaveLength(1);
      expect(res.body.keys[0].provider).toBe("gohighlevel");
    });

    it("deleting a brand key leaves the org key intact", async () => {
      await request(app)
        .post("/keys")
        .set(identity)
        .send({ provider: "gohighlevel", apiKey: "ghl-org-wide-secret" });
      await request(app)
        .put("/keys/gohighlevel/source")
        .set(identity)
        .send({ keySource: "org" });
      await request(app)
        .post(`/keys/brands/${BRAND_A}`)
        .set(identity)
        .send({ provider: "gohighlevel", apiKey: "ghl-brand-a-secret" });

      await request(app)
        .delete(`/keys/brands/${BRAND_A}/gohighlevel`)
        .set(identity)
        .expect(200);

      const org = await request(app)
        .get("/keys/gohighlevel/decrypt")
        .set({ ...identity, ...caller });
      expect(org.body.key).toBe("ghl-org-wide-secret");
    });

    it("deleting the org key leaves the brand keys intact", async () => {
      await request(app)
        .post("/keys")
        .set(identity)
        .send({ provider: "gohighlevel", apiKey: "ghl-org-wide-secret" });
      await request(app)
        .post(`/keys/brands/${BRAND_A}`)
        .set(identity)
        .send({ provider: "gohighlevel", apiKey: "ghl-brand-a-secret" });

      await request(app).delete("/keys/gohighlevel").set(identity).expect(200);

      const a = await request(app)
        .get(`/keys/brands/${BRAND_A}/gohighlevel/decrypt`)
        .set({ ...identity, ...caller });
      expect(a.status).toBe(200);
      expect(a.body.key).toBe("ghl-brand-a-secret");
    });

    it("the platform fallback for an org with no org key is unchanged by brand keys", async () => {
      await request(app)
        .post("/platform-keys")
        .send({ provider: "gohighlevel", apiKey: "ghl-platform-secret" })
        .expect(200);
      await request(app)
        .post(`/keys/brands/${BRAND_A}`)
        .set(identity)
        .send({ provider: "gohighlevel", apiKey: "ghl-brand-a-secret" });

      const res = await request(app)
        .get("/keys/gohighlevel/decrypt")
        .set({ ...identity, ...caller });

      expect(res.status).toBe(200);
      expect(res.body.key).toBe("ghl-platform-secret");
      expect(res.body.keySource).toBe("platform");
    });

    it("a brand key does not satisfy the org-key precondition on switching source to 'org'", async () => {
      await request(app)
        .post(`/keys/brands/${BRAND_A}`)
        .set(identity)
        .send({ provider: "gohighlevel", apiKey: "ghl-brand-a-secret" })
        .expect(200);

      const res = await request(app)
        .put("/keys/gohighlevel/source")
        .set(identity)
        .send({ keySource: "org" });

      expect(res.status).toBe(400);
    });

    it("/keys/brands does not shadow an org-grain provider route", async () => {
      await request(app)
        .post("/keys")
        .set(identity)
        .send({ provider: "sources-lookalike", apiKey: "org-secret" })
        .expect(200);

      const res = await request(app)
        .get("/keys/sources-lookalike/source")
        .set(identity);

      expect(res.status).toBe(200);
      expect(res.body.provider).toBe("sources-lookalike");
    });
  });
});
