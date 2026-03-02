/**
 * Unified key management endpoints.
 * All key operations go through /keys with keySource as a parameter.
 * keySource: "org" (orgId required), "app" (appId required), "platform" (no scope).
 * "byok" is accepted as legacy alias for "org".
 */

import { Router, Request, Response } from "express";
import { eq, and } from "drizzle-orm";
import { db } from "../db/index.js";
import { orgKeys, appKeys, platformKeys } from "../db/schema.js";
import { encrypt, decrypt, maskKey } from "../lib/crypto.js";
import { extractCallerHeaders } from "../lib/caller-headers.js";
import { recordProviderRequirement } from "../lib/provider-registry.js";
import { ensureOrg } from "../lib/ensure-org.js";
import {
  ListKeysQuerySchema,
  UpsertKeyRequestSchema,
  DeleteKeyQuerySchema,
  DecryptKeyQuerySchema,
} from "../schemas.js";

const router = Router();

/** Normalize "byok" → "org" */
function normalizeKeySource(keySource: string): "org" | "app" | "platform" {
  return keySource === "byok" ? "org" : keySource as "org" | "app" | "platform";
}

/**
 * GET /keys
 * List keys by source
 */
router.get("/", async (req: Request, res: Response) => {
  try {
    const parsed = ListKeysQuerySchema.safeParse(req.query);
    if (!parsed.success) {
      return res.status(400).json({ error: "keySource required", details: parsed.error.flatten() });
    }

    const { orgId: externalOrgId, appId } = parsed.data;
    const keySource = normalizeKeySource(parsed.data.keySource);

    if (keySource === "org") {
      if (!externalOrgId) {
        return res.status(400).json({ error: "orgId required for keySource 'org'" });
      }
      const orgId = await ensureOrg(externalOrgId);
      const keys = await db.query.orgKeys.findMany({
        where: eq(orgKeys.orgId, orgId),
      });
      return res.json({
        keys: keys.map((k) => ({
          provider: k.provider,
          maskedKey: maskKey(decrypt(k.encryptedKey)),
          createdAt: k.createdAt,
          updatedAt: k.updatedAt,
        })),
      });
    }

    if (keySource === "app") {
      if (!appId) {
        return res.status(400).json({ error: "appId required for keySource 'app'" });
      }
      const keys = await db.query.appKeys.findMany({
        where: eq(appKeys.appId, appId),
      });
      return res.json({
        keys: keys.map((k) => ({
          provider: k.provider,
          maskedKey: maskKey(decrypt(k.encryptedKey)),
          createdAt: k.createdAt,
          updatedAt: k.updatedAt,
        })),
      });
    }

    // platform
    const keys = await db.query.platformKeys.findMany();
    return res.json({
      keys: keys.map((k) => ({
        provider: k.provider,
        maskedKey: maskKey(decrypt(k.encryptedKey)),
        createdAt: k.createdAt,
        updatedAt: k.updatedAt,
      })),
    });
  } catch (error) {
    console.error("List keys error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

/**
 * POST /keys
 * Upsert a key
 */
router.post("/", async (req: Request, res: Response) => {
  try {
    const parsed = UpsertKeyRequestSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: "Invalid request", details: parsed.error.flatten() });
    }

    const { provider, apiKey, orgId: externalOrgId, appId } = parsed.data;
    const keySource = normalizeKeySource(parsed.data.keySource);
    const encryptedKey = encrypt(apiKey);

    if (keySource === "org") {
      const orgId = await ensureOrg(externalOrgId!);
      const existing = await db.query.orgKeys.findFirst({
        where: and(eq(orgKeys.orgId, orgId), eq(orgKeys.provider, provider)),
      });

      if (existing) {
        await db
          .update(orgKeys)
          .set({ encryptedKey, updatedAt: new Date() })
          .where(eq(orgKeys.id, existing.id));
      } else {
        await db.insert(orgKeys).values({ orgId, provider, encryptedKey });
      }

      return res.json({
        provider,
        maskedKey: maskKey(apiKey),
        message: `${provider} key saved successfully`,
      });
    }

    if (keySource === "app") {
      const existing = await db.query.appKeys.findFirst({
        where: and(eq(appKeys.appId, appId!), eq(appKeys.provider, provider)),
      });

      if (existing) {
        await db
          .update(appKeys)
          .set({ encryptedKey, updatedAt: new Date() })
          .where(eq(appKeys.id, existing.id));
      } else {
        await db.insert(appKeys).values({ appId: appId!, provider, encryptedKey });
      }

      return res.json({
        provider,
        maskedKey: maskKey(apiKey),
        message: `${provider} key saved successfully`,
      });
    }

    // platform
    const existing = await db.query.platformKeys.findFirst({
      where: eq(platformKeys.provider, provider),
    });

    if (existing) {
      await db
        .update(platformKeys)
        .set({ encryptedKey, updatedAt: new Date() })
        .where(eq(platformKeys.id, existing.id));
    } else {
      await db.insert(platformKeys).values({ provider, encryptedKey });
    }

    return res.json({
      provider,
      maskedKey: maskKey(apiKey),
      message: `${provider} key saved successfully`,
    });
  } catch (error) {
    console.error("Upsert key error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

/**
 * DELETE /keys/:provider
 * Delete a key
 */
router.delete("/:provider", async (req: Request, res: Response) => {
  try {
    const { provider } = req.params;
    const parsed = DeleteKeyQuerySchema.safeParse(req.query);
    if (!parsed.success) {
      return res.status(400).json({ error: "keySource required", details: parsed.error.flatten() });
    }

    const { orgId: externalOrgId, appId } = parsed.data;
    const keySource = normalizeKeySource(parsed.data.keySource);

    if (keySource === "org") {
      if (!externalOrgId) {
        return res.status(400).json({ error: "orgId required for keySource 'org'" });
      }
      const orgId = await ensureOrg(externalOrgId);
      await db
        .delete(orgKeys)
        .where(and(eq(orgKeys.orgId, orgId), eq(orgKeys.provider, provider)));
    } else if (keySource === "app") {
      if (!appId) {
        return res.status(400).json({ error: "appId required for keySource 'app'" });
      }
      await db
        .delete(appKeys)
        .where(and(eq(appKeys.appId, appId), eq(appKeys.provider, provider)));
    } else {
      await db
        .delete(platformKeys)
        .where(eq(platformKeys.provider, provider));
    }

    res.json({ provider, message: `${provider} key deleted successfully` });
  } catch (error) {
    console.error("Delete key error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

/**
 * GET /keys/:provider/decrypt
 * Get decrypted key
 */
router.get("/:provider/decrypt", async (req: Request, res: Response) => {
  try {
    const { provider } = req.params;
    const parsed = DecryptKeyQuerySchema.safeParse(req.query);
    if (!parsed.success) {
      return res.status(400).json({ error: "keySource required", details: parsed.error.flatten() });
    }

    const { orgId: externalOrgId, appId } = parsed.data;
    const keySource = normalizeKeySource(parsed.data.keySource);

    const caller = extractCallerHeaders(req);
    if (!caller) {
      return res.status(400).json({
        error: "Missing required headers: X-Caller-Service, X-Caller-Method, X-Caller-Path",
      });
    }

    if (keySource === "org") {
      if (!externalOrgId) {
        return res.status(400).json({ error: "orgId required for keySource 'org'" });
      }
      const orgId = await ensureOrg(externalOrgId);
      const key = await db.query.orgKeys.findFirst({
        where: and(eq(orgKeys.orgId, orgId), eq(orgKeys.provider, provider)),
      });
      if (!key) {
        return res.status(404).json({ error: `Key not found: no '${provider}' key configured for org '${externalOrgId}'` });
      }
      await recordProviderRequirement(caller, provider);
      return res.json({ provider, key: decrypt(key.encryptedKey) });
    }

    if (keySource === "app") {
      if (!appId) {
        return res.status(400).json({ error: "appId required for keySource 'app'" });
      }
      const key = await db.query.appKeys.findFirst({
        where: and(eq(appKeys.appId, appId), eq(appKeys.provider, provider)),
      });
      if (key) {
        await recordProviderRequirement(caller, provider);
        return res.json({ provider, key: decrypt(key.encryptedKey) });
      }

      // Fallback to platform key
      const platformKey = await db.query.platformKeys.findFirst({
        where: eq(platformKeys.provider, provider),
      });
      if (!platformKey) {
        return res.status(404).json({ error: `Key not found: no '${provider}' key configured for app '${appId}'` });
      }
      await recordProviderRequirement(caller, provider);
      return res.json({ provider, key: decrypt(platformKey.encryptedKey) });
    }

    // platform
    const key = await db.query.platformKeys.findFirst({
      where: eq(platformKeys.provider, provider),
    });
    if (!key) {
      return res.status(404).json({ error: `Key not found: no '${provider}' platform key configured` });
    }
    await recordProviderRequirement(caller, provider);
    return res.json({ provider, key: decrypt(key.encryptedKey) });
  } catch (error) {
    console.error("Decrypt key error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

export default router;
