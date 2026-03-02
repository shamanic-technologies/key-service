/**
 * Unified key management endpoints.
 * All key operations go through /keys with keySource as a parameter.
 * keySource: "org" (orgId required), "platform" (no scope).
 * "byok" is accepted as legacy alias for "org".
 *
 * The decrypt endpoint auto-resolves key source via org_provider_key_sources.
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
  ListKeysQuerySchema,
  UpsertKeyRequestSchema,
  DeleteKeyQuerySchema,
  DecryptKeyQuerySchema,
  SetKeySourceRequestSchema,
} from "../schemas.js";

const router = Router();

/** Normalize "byok" → "org" */
function normalizeKeySource(keySource: string): "org" | "platform" {
  return keySource === "byok" ? "org" : keySource as "org" | "platform";
}

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
 * GET /keys
 * List keys by source
 */
router.get("/", async (req: Request, res: Response) => {
  try {
    const parsed = ListKeysQuerySchema.safeParse(req.query);
    if (!parsed.success) {
      return res.status(400).json({ error: "keySource required", details: parsed.error.flatten() });
    }

    const { orgId } = parsed.data;
    const keySource = normalizeKeySource(parsed.data.keySource);

    if (keySource === "org") {
      if (!orgId) {
        return res.status(400).json({ error: "orgId required for keySource 'org'" });
      }
      const keys = await db.query.orgKeys.findMany({
        where: eq(orgKeys.orgId, orgId),
      });
      const result = await Promise.all(
        keys.map(async (k) => {
          const provider = await db.query.providers.findFirst({
            where: eq(providers.id, k.providerId),
          });
          return {
            provider: provider?.name ?? "unknown",
            maskedKey: maskKey(decrypt(k.encryptedKey)),
            createdAt: k.createdAt,
            updatedAt: k.updatedAt,
          };
        })
      );
      return res.json({ keys: result });
    }

    // platform
    const keys = await db.query.platformKeys.findMany();
    const result = await Promise.all(
      keys.map(async (k) => {
        const provider = await db.query.providers.findFirst({
          where: eq(providers.id, k.providerId),
        });
        return {
          provider: provider?.name ?? "unknown",
          maskedKey: maskKey(decrypt(k.encryptedKey)),
          createdAt: k.createdAt,
          updatedAt: k.updatedAt,
        };
      })
    );
    return res.json({ keys: result });
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

    const { provider: providerName, apiKey, orgId } = parsed.data;
    const keySource = normalizeKeySource(parsed.data.keySource);
    const providerId = await ensureProvider(providerName);
    const encryptedKey = encrypt(apiKey);

    if (keySource === "org") {
      const existing = await db.query.orgKeys.findFirst({
        where: and(eq(orgKeys.orgId, orgId!), eq(orgKeys.providerId, providerId)),
      });

      if (existing) {
        await db
          .update(orgKeys)
          .set({ encryptedKey, updatedAt: new Date() })
          .where(eq(orgKeys.id, existing.id));
      } else {
        await db.insert(orgKeys).values({ orgId: orgId!, providerId, encryptedKey });
      }

      return res.json({
        provider: providerName,
        maskedKey: maskKey(apiKey),
        message: `${providerName} key saved successfully`,
      });
    }

    // platform
    const existing = await db.query.platformKeys.findFirst({
      where: eq(platformKeys.providerId, providerId),
    });

    if (existing) {
      await db
        .update(platformKeys)
        .set({ encryptedKey, updatedAt: new Date() })
        .where(eq(platformKeys.id, existing.id));
    } else {
      await db.insert(platformKeys).values({ providerId, encryptedKey });
    }

    return res.json({
      provider: providerName,
      maskedKey: maskKey(apiKey),
      message: `${providerName} key saved successfully`,
    });
  } catch (error) {
    console.error("Upsert key error:", error);
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
      return res.status(400).json({ error: "orgId required", details: parsed.error.flatten() });
    }

    const { orgId } = parsed.data;

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
      return res.json({ provider: providerName, key: decrypt(key.encryptedKey), keySource: "org" });
    }

    // platform
    const key = await db.query.platformKeys.findFirst({
      where: eq(platformKeys.providerId, provider.id),
    });
    if (!key) {
      return res.status(404).json({ error: `Key not found: no '${providerName}' platform key configured` });
    }
    await recordProviderRequirement(caller, providerName);
    return res.json({ provider: providerName, key: decrypt(key.encryptedKey), keySource: "platform" });
  } catch (error) {
    console.error("Decrypt key error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

/**
 * DELETE /keys/:provider
 * Delete a key
 */
router.delete("/:provider", async (req: Request, res: Response) => {
  try {
    const { provider: providerName } = req.params;
    const parsed = DeleteKeyQuerySchema.safeParse(req.query);
    if (!parsed.success) {
      return res.status(400).json({ error: "keySource required", details: parsed.error.flatten() });
    }

    const { orgId } = parsed.data;
    const keySource = normalizeKeySource(parsed.data.keySource);

    const provider = await getProviderByName(providerName);

    if (keySource === "org") {
      if (!orgId) {
        return res.status(400).json({ error: "orgId required for keySource 'org'" });
      }
      if (provider) {
        await db
          .delete(orgKeys)
          .where(and(eq(orgKeys.orgId, orgId), eq(orgKeys.providerId, provider.id)));
      }
    } else {
      if (provider) {
        await db
          .delete(platformKeys)
          .where(eq(platformKeys.providerId, provider.id));
      }
    }

    res.json({ provider: providerName, message: `${providerName} key deleted successfully` });
  } catch (error) {
    console.error("Delete key error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

export default router;
