/**
 * Key resolve and preference endpoints.
 * The decrypt endpoint auto-resolves key source via org_provider_key_sources.
 * CRUD operations use /internal/keys (org) and /internal/platform-keys (platform).
 */

import { Router, Request, Response } from "express";
import { eq, and } from "drizzle-orm";
import { db } from "../db/index.js";
import { orgKeys, platformKeys, providers, orgProviderKeySources } from "../db/schema.js";
import { decrypt } from "../lib/crypto.js";
import { extractCallerHeaders } from "../lib/caller-headers.js";
import { recordProviderRequirement } from "../lib/provider-registry.js";
import { ensureProvider, getProviderByName } from "../lib/ensure-provider.js";
import {
  DecryptKeyQuerySchema,
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

/**
 * GET /keys/sources
 * List all key source preferences for an org
 * NOTE: this must be before /:provider routes to avoid conflict
 */
router.get("/sources", async (req: Request, res: Response) => {
  try {
    const orgId = req.query.orgId as string;
    if (!orgId) {
      return res.status(400).json({ error: "orgId required" });
    }

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
 * Set key source preference for an org+provider
 */
router.put("/:provider/source", async (req: Request, res: Response) => {
  try {
    const { provider: providerName } = req.params;
    const parsed = SetKeySourceRequestSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: "Invalid request", details: parsed.error.flatten() });
    }

    const { orgId, keySource } = parsed.data;
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
 * Get key source preference for an org+provider
 */
router.get("/:provider/source", async (req: Request, res: Response) => {
  try {
    const { provider: providerName } = req.params;
    const orgId = req.query.orgId as string;

    if (!orgId) {
      return res.status(400).json({ error: "orgId required" });
    }

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
    const parsed = DecryptKeyQuerySchema.safeParse(req.query);
    if (!parsed.success) {
      return res.status(400).json({ error: "orgId and userId required", details: parsed.error.flatten() });
    }

    const { orgId, userId } = parsed.data;

    const caller = extractCallerHeaders(req);
    if (!caller) {
      return res.status(400).json({
        error: "Missing required headers: X-Caller-Service, X-Caller-Method, X-Caller-Path",
      });
    }

    const provider = await getProviderByName(providerName);
    if (!provider) {
      return res.status(404).json({ error: `Key not found: no '${providerName}' key configured` });
    }

    const keySource = await resolveKeySource(orgId, provider.id);

    if (keySource === "org") {
      const key = await db.query.orgKeys.findFirst({
        where: and(eq(orgKeys.orgId, orgId), eq(orgKeys.providerId, provider.id)),
      });
      if (!key) {
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
      return res.status(404).json({ error: `Key not found: no '${providerName}' platform key configured` });
    }
    await recordProviderRequirement(caller, providerName);
    return res.json({ provider: providerName, key: decrypt(key.encryptedKey), keySource: "platform", userId });
  } catch (error) {
    console.error("Decrypt key error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

export default router;
