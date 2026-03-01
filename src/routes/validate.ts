import { Router } from "express";
import { eq, and } from "drizzle-orm";
import { db } from "../db/index.js";
import { orgs, byokKeys } from "../db/schema.js";
import { apiKeyAuth, AuthenticatedRequest } from "../middleware/auth.js";
import { decrypt } from "../lib/crypto.js";
import { extractCallerHeaders } from "../lib/caller-headers.js";
import { recordProviderRequirement } from "../lib/provider-registry.js";

const router = Router();

/**
 * GET /validate - Validate API key and return identity info
 * - User key (mcpf_*): returns { valid, type: "user", orgId, configuredProviders }
 * - App key (mcpf_app_*): returns { valid, type: "app", appId }
 */
router.get("/validate", apiKeyAuth, async (req: AuthenticatedRequest, res) => {
  try {
    // App key: return appId
    if (req.authType === "app_key") {
      return res.json({
        valid: true,
        type: "app",
        appId: req.appId,
      });
    }

    // User key: return appId + orgId + userId + configured providers
    const org = await db.query.orgs.findFirst({
      where: eq(orgs.id, req.orgId!),
    });

    if (!org) {
      return res.status(404).json({ error: "Organization not found" });
    }

    const keys = await db.query.byokKeys.findMany({
      where: eq(byokKeys.orgId, req.orgId!),
    });

    const configuredProviders = keys.map((k) => k.provider);

    res.json({
      valid: true,
      type: "user",
      appId: req.appId,
      orgId: org.orgId,
      userId: req.userId,
      configuredProviders,
    });
  } catch (error) {
    console.error("Validate error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

/**
 * GET /validate/keys/:provider - Get decrypted BYOK key (for MCP internal use)
 * Only works with user keys (not app keys)
 */
router.get("/validate/keys/:provider", apiKeyAuth, async (req: AuthenticatedRequest, res) => {
  try {
    if (req.authType === "app_key") {
      return res.status(400).json({ error: "BYOK key lookup requires a user API key, not an app key" });
    }

    const { provider } = req.params;

    const caller = extractCallerHeaders(req);
    if (!caller) {
      return res.status(400).json({
        error: "Missing required headers: X-Caller-Service, X-Caller-Method, X-Caller-Path",
      });
    }

    const key = await db.query.byokKeys.findFirst({
      where: and(
        eq(byokKeys.orgId, req.orgId!),
        eq(byokKeys.provider, provider)
      ),
    });

    if (!key) {
      return res.status(404).json({ error: `BYOK key not found: no '${provider}' key configured for this org` });
    }

    await recordProviderRequirement(caller, provider);

    res.json({
      provider,
      key: decrypt(key.encryptedKey),
    });
  } catch (error) {
    console.error("Get BYOK key error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

export default router;
