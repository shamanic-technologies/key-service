/**
 * Key resolve, preference, and org key CRUD endpoints.
 * Mounted at /keys — requires identity headers.
 */

import { Router, Request, Response } from "express";
import { eq, and } from "drizzle-orm";
import { db } from "../db/index.js";
import { orgKeys, platformKeys, providers, orgProviderKeySources } from "../db/schema.js";
import { encrypt, decrypt, maskKey } from "../lib/crypto.js";
import { extractCallerHeaders } from "../lib/caller-headers.js";
import { recordProviderRequirement } from "../lib/provider-registry.js";
import { ensureProvider, getProviderByName } from "../lib/ensure-provider.js";
import {
  CreateOrgKeyRequestSchema,
  SetKeySourceRequestSchema,
} from "../schemas.js";

const router = Router();

/** Resolve key source preference for an org+provider. Default = "platform". */
async function resolveKeySource(orgId: string, providerId: string): Promise<"org" | "platform"> {
  const pref = await db.query.orgProviderKeySources.findFirst({
    where: and(
      eq(orgProviderKeySources.orgId, orgId),
      eq(orgProviderKeySources.providerId, providerId),
    ),
  });
  return (pref?.keySource as "org" | "platform") ?? "platform";
}

// ==================== ORG KEY CRUD ====================

/**
 * GET /keys
 * List org keys for the caller's org
 */
router.get("/", async (req: Request, res: Response) => {
  try {
    const { orgId } = req.identity!;

    const keys = await db.query.orgKeys.findMany({
      where: eq(orgKeys.orgId, orgId),
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

    res.json({ keys: maskedKeys });
  } catch (error) {
    console.error("List keys error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

/**
 * POST /keys
 * Add or update an org key
 */
router.post("/", async (req: Request, res: Response) => {
  try {
    const parsed = CreateOrgKeyRequestSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: "Invalid request", details: parsed.error.flatten() });
    }

    const { orgId } = req.identity!;
    const { provider: providerName, apiKey } = parsed.data;
    const providerId = await ensureProvider(providerName);
    const encryptedKey = encrypt(apiKey);

    // Upsert
    const existing = await db.query.orgKeys.findFirst({
      where: and(eq(orgKeys.orgId, orgId), eq(orgKeys.providerId, providerId)),
    });

    if (existing) {
      await db
        .update(orgKeys)
        .set({ encryptedKey, updatedAt: new Date() })
        .where(eq(orgKeys.id, existing.id));
    } else {
      await db.insert(orgKeys).values({
        orgId,
        providerId,
        encryptedKey,
      });
    }

    res.json({
      provider: providerName,
      maskedKey: maskKey(apiKey),
      message: `${providerName} key saved successfully`,
    });
  } catch (error) {
    console.error("Set key error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

/**
 * DELETE /keys/:provider
 * Delete an org key — but must not conflict with /keys/sources or /keys/platform
 * We handle this by placing this route after more specific routes.
 */

// ==================== KEY SOURCE PREFERENCES ====================

/**
 * GET /keys/sources
 * List all key source preferences for the caller's org
 * NOTE: this must be before /:provider routes to avoid conflict
 */
router.get("/sources", async (req: Request, res: Response) => {
  try {
    const { orgId } = req.identity!;

    const prefs = await db.query.orgProviderKeySources.findMany({
      where: eq(orgProviderKeySources.orgId, orgId),
    });

    const sources = await Promise.all(
      prefs.map(async (pref) => {
        const provider = await db.query.providers.findFirst({
          where: eq(providers.id, pref.providerId),
        });
        return {
          provider: provider?.name ?? "unknown",
          keySource: pref.keySource as "org" | "platform",
        };
      })
    );

    res.json({ sources });
  } catch (error) {
    console.error("List key sources error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

/**
 * PUT /keys/:provider/source
 * Set key source preference for the caller's org + provider
 */
router.put("/:provider/source", async (req: Request, res: Response) => {
  try {
    const { provider: providerName } = req.params;
    const parsed = SetKeySourceRequestSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: "Invalid request", details: parsed.error.flatten() });
    }

    const { orgId } = req.identity!;
    const { keySource } = parsed.data;
    const providerId = await ensureProvider(providerName);

    // If switching to "org", verify org key exists
    if (keySource === "org") {
      const orgKey = await db.query.orgKeys.findFirst({
        where: and(eq(orgKeys.orgId, orgId), eq(orgKeys.providerId, providerId)),
      });
      if (!orgKey) {
        return res.status(400).json({
          error: `No org key stored for provider '${providerName}'. Store an org key first before switching to 'org' source.`,
        });
      }
    }

    // Upsert preference
    const existing = await db.query.orgProviderKeySources.findFirst({
      where: and(
        eq(orgProviderKeySources.orgId, orgId),
        eq(orgProviderKeySources.providerId, providerId),
      ),
    });

    if (existing) {
      await db
        .update(orgProviderKeySources)
        .set({ keySource, updatedAt: new Date() })
        .where(eq(orgProviderKeySources.id, existing.id));
    } else {
      await db.insert(orgProviderKeySources).values({
        orgId,
        providerId,
        keySource,
      });
    }

    res.json({
      provider: providerName,
      orgId,
      keySource,
      message: `Key source for '${providerName}' set to '${keySource}'`,
    });
  } catch (error) {
    console.error("Set key source error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

/**
 * GET /keys/:provider/source
 * Get key source preference for the caller's org + provider
 */
router.get("/:provider/source", async (req: Request, res: Response) => {
  try {
    const { provider: providerName } = req.params;
    const { orgId } = req.identity!;

    const provider = await getProviderByName(providerName);
    if (!provider) {
      return res.json({
        provider: providerName,
        orgId,
        keySource: "platform",
        isDefault: true,
      });
    }

    const pref = await db.query.orgProviderKeySources.findFirst({
      where: and(
        eq(orgProviderKeySources.orgId, orgId),
        eq(orgProviderKeySources.providerId, provider.id),
      ),
    });

    res.json({
      provider: providerName,
      orgId,
      keySource: (pref?.keySource as "org" | "platform") ?? "platform",
      isDefault: !pref,
    });
  } catch (error) {
    console.error("Get key source error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

/**
 * GET /keys/:provider/decrypt
 * Get decrypted key — auto-resolves source via org_provider_key_sources
 */
router.get("/:provider/decrypt", async (req: Request, res: Response) => {
  try {
    const { provider: providerName } = req.params;
    const { orgId, userId } = req.identity!;

    const caller = extractCallerHeaders(req);
    if (!caller) {
      return res.status(400).json({
        error: "Missing required headers: X-Caller-Service, X-Caller-Method, X-Caller-Path",
      });
    }

    const provider = await getProviderByName(providerName);
    if (!provider) {
      console.warn(`[key-service] GET /keys/${providerName}/decrypt → 404: provider not found in providers table (orgId=${orgId})`);
      return res.status(404).json({ error: `Key not found: no '${providerName}' key configured` });
    }

    const keySource = await resolveKeySource(orgId, provider.id);

    if (keySource === "org") {
      const key = await db.query.orgKeys.findFirst({
        where: and(eq(orgKeys.orgId, orgId), eq(orgKeys.providerId, provider.id)),
      });
      if (!key) {
        console.warn(`[key-service] GET /keys/${providerName}/decrypt → 404: no org key for orgId=${orgId}`);
        return res.status(404).json({ error: `Key not found: no '${providerName}' org key configured for org '${orgId}'` });
      }
      await recordProviderRequirement(caller, providerName);
      return res.json({ provider: providerName, key: decrypt(key.encryptedKey), keySource: "org", userId });
    }

    // platform
    const key = await db.query.platformKeys.findFirst({
      where: eq(platformKeys.providerId, provider.id),
    });
    if (!key) {
      console.warn(`[key-service] GET /keys/${providerName}/decrypt → 404: provider exists but no platform key row`);
      return res.status(404).json({ error: `Key not found: no '${providerName}' platform key configured` });
    }
    await recordProviderRequirement(caller, providerName);
    return res.json({ provider: providerName, key: decrypt(key.encryptedKey), keySource: "platform", userId });
  } catch (error) {
    console.error("Decrypt key error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Place delete after specific routes to avoid catching /sources, /platform, etc.
/**
 * DELETE /keys/:provider
 * Delete an org key
 */
router.delete("/:provider", async (req: Request, res: Response) => {
  try {
    const { provider: providerName } = req.params;
    const { orgId } = req.identity!;

    const provider = await getProviderByName(providerName);
    if (provider) {
      await db
        .delete(orgKeys)
        .where(and(eq(orgKeys.orgId, orgId), eq(orgKeys.providerId, provider.id)));
    }

    res.json({
      provider: providerName,
      message: `${providerName} key deleted successfully`,
    });
  } catch (error) {
    console.error("Delete key error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

export default router;
