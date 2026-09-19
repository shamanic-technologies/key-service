/**
 * Brand-scoped third-party credential CRUD and resolution.
 * Mounted at /keys/brands — requires identity headers.
 *
 * One agency org holds many brands, each of which is a different end client
 * with its own sub-account at the same provider. These routes are a second
 * GRAIN beside the org-wide routes in keys.ts, never a replacement: a
 * brand-scoped read resolves brand rows only. If the brand has no credential
 * for the provider, the answer is 404 — the org-wide credential is never
 * substituted, and neither is another brand's.
 */

import { Router, Request, Response } from "express";
import { eq, and } from "drizzle-orm";
import { db } from "../db/index.js";
import { brandKeys, providers } from "../db/schema.js";
import { encrypt, decrypt, maskKey } from "../lib/crypto.js";
import { extractCallerHeaders } from "../lib/caller-headers.js";
import { recordProviderRequirement } from "../lib/provider-registry.js";
import { ensureProvider, getProviderByName } from "../lib/ensure-provider.js";
import { traceEvent } from "../lib/trace-event.js";
import { CreateBrandKeyRequestSchema } from "../schemas.js";

const router = Router();

/**
 * GET /keys/brands/:brandId
 * List this brand's credentials, masked.
 */
router.get("/:brandId", async (req: Request, res: Response) => {
  try {
    const { brandId } = req.params;
    const { orgId } = req.identity!;

    const keys = await db.query.brandKeys.findMany({
      where: and(eq(brandKeys.orgId, orgId), eq(brandKeys.brandId, brandId)),
    });

    const maskedKeys = await Promise.all(
      keys.map(async (key) => {
        const provider = await db.query.providers.findFirst({
          where: eq(providers.id, key.providerId),
        });
        return {
          provider: provider?.name ?? "unknown",
          maskedKey: maskKey(decrypt(key.encryptedKey)),
          createdAt: key.createdAt,
          updatedAt: key.updatedAt,
        };
      })
    );

    res.json({ brandId, keys: maskedKeys });
  } catch (error) {
    console.error("List brand keys error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

/**
 * POST /keys/brands/:brandId
 * Add or update this brand's credential for a provider.
 *
 * The upsert is keyed on (orgId, brandId, providerId), so storing brand A's
 * credential cannot touch brand B's row for the same provider, nor the org's.
 */
router.post("/:brandId", async (req: Request, res: Response) => {
  try {
    const parsed = CreateBrandKeyRequestSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: "Invalid request", details: parsed.error.flatten() });
    }

    const { brandId } = req.params;
    const { orgId } = req.identity!;
    const { provider: providerName, apiKey } = parsed.data;
    const providerId = await ensureProvider(providerName);
    const encryptedKey = encrypt(apiKey);

    const existing = await db.query.brandKeys.findFirst({
      where: and(
        eq(brandKeys.orgId, orgId),
        eq(brandKeys.brandId, brandId),
        eq(brandKeys.providerId, providerId)
      ),
    });

    if (existing) {
      await db
        .update(brandKeys)
        .set({ encryptedKey, updatedAt: new Date() })
        .where(eq(brandKeys.id, existing.id));
    } else {
      await db.insert(brandKeys).values({ orgId, brandId, providerId, encryptedKey });
    }

    const runId = req.headers["x-run-id"] as string | undefined;
    if (runId) {
      traceEvent(runId, {
        service: "key-service",
        event: "brand-key-saved",
        detail: `Brand key ${existing ? "updated" : "created"} for provider=${providerName}, brandId=${brandId}`,
        data: { provider: providerName, brandId, action: existing ? "update" : "create" },
      }, req.headers).catch(() => {});
    }

    res.json({
      brandId,
      provider: providerName,
      maskedKey: maskKey(apiKey),
      message: `${providerName} key saved successfully for brand ${brandId}`,
    });
  } catch (error) {
    console.error("Set brand key error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

/**
 * GET /keys/brands/:brandId/:provider/decrypt
 * Resolve this brand's credential, decrypted. Service-to-service only.
 *
 * No fallback: an absent brand credential is a 404, never the org-wide one.
 */
router.get("/:brandId/:provider/decrypt", async (req: Request, res: Response) => {
  try {
    const { brandId, provider: providerName } = req.params;
    const { orgId, userId } = req.identity!;

    const caller = extractCallerHeaders(req);
    if (!caller) {
      return res.status(400).json({
        error: "Missing required headers: X-Caller-Service, X-Caller-Method, X-Caller-Path",
      });
    }

    const provider = await getProviderByName(providerName);
    if (!provider) {
      console.warn(`[key-service] GET /keys/brands/${brandId}/${providerName}/decrypt → 404: provider not found in providers table (orgId=${orgId})`);
      return res.status(404).json({
        error: `Key not found: no '${providerName}' key configured for brand '${brandId}'`,
      });
    }

    const key = await db.query.brandKeys.findFirst({
      where: and(
        eq(brandKeys.orgId, orgId),
        eq(brandKeys.brandId, brandId),
        eq(brandKeys.providerId, provider.id)
      ),
    });

    if (!key) {
      console.warn(`[key-service] GET /keys/brands/${brandId}/${providerName}/decrypt → 404: no brand key for orgId=${orgId}`);
      return res.status(404).json({
        error: `Key not found: no '${providerName}' brand key configured for brand '${brandId}' of org '${orgId}'`,
      });
    }

    const runId = req.headers["x-run-id"] as string | undefined;
    if (runId) {
      traceEvent(runId, {
        service: "key-service",
        event: "brand-decrypt-resolve",
        detail: `Resolving ${providerName} key for brandId=${brandId}, orgId=${orgId}`,
        data: { provider: providerName, brandId, orgId },
      }, req.headers).catch(() => {});
    }

    await recordProviderRequirement(caller, providerName);
    return res.json({
      brandId,
      provider: providerName,
      key: decrypt(key.encryptedKey),
      keySource: "brand",
      userId,
    });
  } catch (error) {
    console.error("Decrypt brand key error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

/**
 * DELETE /keys/brands/:brandId/:provider
 * Delete this brand's credential for a provider. Leaves every other brand's
 * row and the org-wide row untouched.
 */
router.delete("/:brandId/:provider", async (req: Request, res: Response) => {
  try {
    const { brandId, provider: providerName } = req.params;
    const { orgId } = req.identity!;

    const provider = await getProviderByName(providerName);
    if (provider) {
      await db
        .delete(brandKeys)
        .where(
          and(
            eq(brandKeys.orgId, orgId),
            eq(brandKeys.brandId, brandId),
            eq(brandKeys.providerId, provider.id)
          )
        );
    }

    res.json({
      brandId,
      provider: providerName,
      message: `${providerName} key deleted successfully for brand ${brandId}`,
    });
  } catch (error) {
    console.error("Delete brand key error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

export default router;
