import { Router, Request, Response } from "express";
import { eq, and } from "drizzle-orm";
import { db } from "../db/index.js";
import { userAuthKeys, orgKeys, providers } from "../db/schema.js";
import { hashApiKey, hasValidPrefix } from "../lib/api-key.js";
import { decrypt } from "../lib/crypto.js";
import { extractCallerHeaders } from "../lib/caller-headers.js";
import { recordProviderRequirement } from "../lib/provider-registry.js";

const router = Router();

/**
 * Resolve an API key string to identity info.
 * Returns null if the key is invalid.
 */
async function resolveApiKey(key: string) {
  if (!hasValidPrefix(key)) return null;

  const keyHash = hashApiKey(key);

  const userKey = await db.query.userAuthKeys.findFirst({
    where: eq(userAuthKeys.keyHash, keyHash),
  });
  if (!userKey) return null;

  // Update last used
  await db
    .update(userAuthKeys)
    .set({ lastUsedAt: new Date() })
    .where(eq(userAuthKeys.id, userKey.id));

  return {
    orgId: userKey.orgId,
    userId: userKey.userId,
  };
}

/**
 * GET /validate?key=distrib.usr_xxx - Validate API key and return identity info
 * Auth: serviceKeyAuth (X-API-Key)
 * Returns: { valid, type: "user", orgId, userId, configuredProviders }
 */
router.get("/validate", async (req: Request, res: Response) => {
  try {
    const key = typeof req.query.key === "string" ? req.query.key : null;
    if (!key) {
      return res.status(400).json({ error: "Missing required query parameter: key" });
    }

    const identity = await resolveApiKey(key);
    if (!identity) {
      return res.status(401).json({ error: "Invalid API key" });
    }

    // Get configured org providers
    const keys = await db.query.orgKeys.findMany({
      where: eq(orgKeys.orgId, identity.orgId),
      with: { },
    });

    // Resolve provider names
    const configuredProviders: string[] = [];
    for (const k of keys) {
      const provider = await db.query.providers.findFirst({
        where: eq(providers.id, k.providerId),
      });
      if (provider) {
        configuredProviders.push(provider.name);
      }
    }

    res.json({
      valid: true,
      type: "user",
      orgId: identity.orgId,
      userId: identity.userId,
      configuredProviders,
    });
  } catch (error) {
    console.error("Validate error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

/**
 * GET /validate/keys/:provider?key=distrib.usr_xxx - Get decrypted org key
 * Auth: serviceKeyAuth (X-API-Key)
 */
router.get("/validate/keys/:provider", async (req: Request, res: Response) => {
  try {
    const key = typeof req.query.key === "string" ? req.query.key : null;
    if (!key) {
      return res.status(400).json({ error: "Missing required query parameter: key" });
    }

    const identity = await resolveApiKey(key);
    if (!identity) {
      return res.status(401).json({ error: "Invalid API key" });
    }

    const { provider: providerName } = req.params;

    const caller = extractCallerHeaders(req);
    if (!caller) {
      return res.status(400).json({
        error: "Missing required headers: X-Caller-Service, X-Caller-Method, X-Caller-Path",
      });
    }

    // Resolve provider name to ID
    const provider = await db.query.providers.findFirst({
      where: eq(providers.name, providerName),
    });

    if (!provider) {
      return res.status(404).json({ error: `Key not found: no '${providerName}' key configured for this org` });
    }

    const orgKey = await db.query.orgKeys.findFirst({
      where: and(
        eq(orgKeys.orgId, identity.orgId),
        eq(orgKeys.providerId, provider.id)
      ),
    });

    if (!orgKey) {
      return res.status(404).json({ error: `Key not found: no '${providerName}' key configured for this org` });
    }

    await recordProviderRequirement(caller, providerName);

    res.json({
      provider: providerName,
      key: decrypt(orgKey.encryptedKey),
    });
  } catch (error) {
    console.error("Get org key error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

export default router;
