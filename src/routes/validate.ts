import { Router, Request, Response } from "express";
import { eq, and } from "drizzle-orm";
import { db } from "../db/index.js";
import { apiKeys, apps, orgs, orgKeys } from "../db/schema.js";
import { hashApiKey, isAppApiKey, hasValidPrefix } from "../lib/api-key.js";
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

  if (isAppApiKey(key)) {
    const app = await db.query.apps.findFirst({
      where: eq(apps.keyHash, keyHash),
    });
    if (!app) return null;
    return { authType: "app_key" as const, appId: app.name };
  }

  const apiKey = await db.query.apiKeys.findFirst({
    where: eq(apiKeys.keyHash, keyHash),
  });
  if (!apiKey) return null;

  // Update last used
  await db
    .update(apiKeys)
    .set({ lastUsedAt: new Date() })
    .where(eq(apiKeys.id, apiKey.id));

  return {
    authType: "user_key" as const,
    appId: apiKey.appId,
    orgId: apiKey.orgId,
    userId: apiKey.userId,
  };
}

/**
 * GET /validate?key=distrib.usr_xxx - Validate API key and return identity info
 * Auth: serviceKeyAuth (X-API-Key)
 * - User key: returns { valid, type: "user", appId, orgId, userId, configuredProviders }
 * - App key: returns { valid, type: "app", appId }
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

    if (identity.authType === "app_key") {
      return res.json({
        valid: true,
        type: "app",
        appId: identity.appId,
      });
    }

    // User key: return appId + orgId + userId + configured providers
    const org = await db.query.orgs.findFirst({
      where: eq(orgs.id, identity.orgId!),
    });

    if (!org) {
      return res.status(404).json({ error: "Organization not found" });
    }

    const keys = await db.query.orgKeys.findMany({
      where: eq(orgKeys.orgId, identity.orgId!),
    });

    const configuredProviders = keys.map((k) => k.provider);

    res.json({
      valid: true,
      type: "user",
      appId: identity.appId,
      orgId: org.orgId,
      userId: identity.userId,
      configuredProviders,
    });
  } catch (error) {
    console.error("Validate error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

/**
 * GET /validate/keys/:provider?key=distrib.usr_xxx - Get decrypted BYOK key
 * Auth: serviceKeyAuth (X-API-Key)
 * Only works with user keys (not app keys)
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

    if (identity.authType === "app_key") {
      return res.status(400).json({ error: "BYOK key lookup requires a user API key, not an app key" });
    }

    const { provider } = req.params;

    const caller = extractCallerHeaders(req);
    if (!caller) {
      return res.status(400).json({
        error: "Missing required headers: X-Caller-Service, X-Caller-Method, X-Caller-Path",
      });
    }

    const orgKey = await db.query.orgKeys.findFirst({
      where: and(
        eq(orgKeys.orgId, identity.orgId!),
        eq(orgKeys.provider, provider)
      ),
    });

    if (!orgKey) {
      return res.status(404).json({ error: `BYOK key not found: no '${provider}' key configured for this org` });
    }

    await recordProviderRequirement(caller, provider);

    res.json({
      provider,
      key: decrypt(orgKey.encryptedKey),
    });
  } catch (error) {
    console.error("Get BYOK key error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

export default router;
