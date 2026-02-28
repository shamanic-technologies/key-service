/**
 * Internal routes for service-to-service calls
 * No auth needed - Railway private network
 */

import { Router, Request, Response } from "express";
import { eq, and } from "drizzle-orm";
import { db } from "../db/index.js";
import { apiKeys, appKeys, apps, byokKeys, orgs, platformKeys, providerRequirements } from "../db/schema.js";
import { generateApiKey, generateAppApiKey, hashApiKey, getKeyPrefix } from "../lib/api-key.js";
import { encrypt, decrypt, maskKey } from "../lib/crypto.js";
import { extractCallerHeaders } from "../lib/caller-headers.js";
import { recordProviderRequirement } from "../lib/provider-registry.js";
import {
  CreateApiKeyRequestSchema,
  DeleteApiKeyRequestSchema,
  SessionApiKeyRequestSchema,
  CreateByokKeyRequestSchema,
  DeleteByokKeyQuerySchema,
  CreateAppKeyRequestSchema,
  DeleteAppKeyQuerySchema,
  CreatePlatformKeyRequestSchema,
  ProviderRequirementsRequestSchema,
  RegisterAppRequestSchema,
} from "../schemas.js";

const router = Router();

const VALID_PROVIDERS = ["apollo", "anthropic", "instantly", "firecrawl"];

// No auth middleware needed - Railway private network

/**
 * Ensure org exists, creating if needed
 */
async function ensureOrg(orgId: string): Promise<string> {
  let org = await db.query.orgs.findFirst({
    where: eq(orgs.orgId, orgId),
  });

  if (!org) {
    const [newOrg] = await db
      .insert(orgs)
      .values({ orgId })
      .returning();
    org = newOrg;
  }

  return org.id;
}

// ==================== API KEYS ====================

/**
 * GET /internal/api-keys
 * List API keys for an org (by orgId)
 */
router.get("/api-keys", async (req: Request, res: Response) => {
  try {
    const { orgId: externalOrgId } = req.query;

    if (!externalOrgId || typeof externalOrgId !== "string") {
      return res.status(400).json({ error: "orgId required" });
    }

    const orgId = await ensureOrg(externalOrgId);

    const keys = await db.query.apiKeys.findMany({
      where: eq(apiKeys.orgId, orgId),
    });

    res.json({
      keys: keys.map((k) => ({
        id: k.id,
        keyPrefix: k.keyPrefix,
        name: k.name,
        createdAt: k.createdAt,
        lastUsedAt: k.lastUsedAt,
      })),
    });
  } catch (error) {
    console.error("List API keys error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

/**
 * POST /internal/api-keys
 * Create a new API key
 */
router.post("/api-keys", async (req: Request, res: Response) => {
  try {
    const parsed = CreateApiKeyRequestSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: "Invalid request", details: parsed.error.flatten() });
    }

    const { orgId: externalOrgId, name } = parsed.data;
    const orgId = await ensureOrg(externalOrgId);

    const rawKey = generateApiKey();
    const keyHash = hashApiKey(rawKey);
    const keyPrefix = getKeyPrefix(rawKey);

    const [apiKey] = await db
      .insert(apiKeys)
      .values({
        orgId,
        keyHash,
        keyPrefix,
        name: name || null,
      })
      .returning();

    res.json({
      id: apiKey.id,
      key: rawKey,
      keyPrefix: apiKey.keyPrefix,
      name: apiKey.name,
      message: "API key created. Save this key - it won't be shown again.",
    });
  } catch (error) {
    console.error("Create API key error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

/**
 * DELETE /internal/api-keys/:id
 * Delete an API key
 */
router.delete("/api-keys/:id", async (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const parsed = DeleteApiKeyRequestSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: "orgId required" });
    }

    const { orgId: externalOrgId } = parsed.data;
    const orgId = await ensureOrg(externalOrgId);

    const result = await db
      .delete(apiKeys)
      .where(and(eq(apiKeys.id, id), eq(apiKeys.orgId, orgId)))
      .returning();

    if (result.length === 0) {
      return res.status(404).json({ error: "API key not found" });
    }

    res.json({ message: "API key deleted successfully" });
  } catch (error) {
    console.error("Delete API key error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

/**
 * POST /internal/api-keys/session
 * Get or create a "Default" API key for the org.
 * Stores the key encrypted so it can be retrieved on future calls.
 */
router.post("/api-keys/session", async (req: Request, res: Response) => {
  try {
    const parsed = SessionApiKeyRequestSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: "orgId required" });
    }

    const { orgId: externalOrgId } = parsed.data;
    const orgId = await ensureOrg(externalOrgId);

    const existing = await db.query.apiKeys.findFirst({
      where: and(eq(apiKeys.orgId, orgId), eq(apiKeys.name, "Default")),
    });

    // Return existing key (decrypt from storage)
    if (existing?.encryptedKey) {
      return res.json({
        id: existing.id,
        key: decrypt(existing.encryptedKey),
        keyPrefix: existing.keyPrefix,
        name: existing.name,
      });
    }

    // Clean up legacy key without encryptedKey
    if (existing) {
      await db.delete(apiKeys).where(eq(apiKeys.id, existing.id));
    }

    // Create new Default key with encrypted storage
    const rawKey = generateApiKey();
    const keyHash = hashApiKey(rawKey);
    const keyPrefix = getKeyPrefix(rawKey);

    const [apiKey] = await db
      .insert(apiKeys)
      .values({
        orgId,
        keyHash,
        keyPrefix,
        encryptedKey: encrypt(rawKey),
        name: "Default",
      })
      .returning();

    res.json({
      id: apiKey.id,
      key: rawKey,
      keyPrefix: apiKey.keyPrefix,
      name: apiKey.name,
    });
  } catch (error) {
    console.error("Session API key error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ==================== BYOK KEYS ====================

/**
 * GET /internal/keys
 * List BYOK keys for an org
 */
router.get("/keys", async (req: Request, res: Response) => {
  try {
    const { orgId: externalOrgId } = req.query;

    if (!externalOrgId || typeof externalOrgId !== "string") {
      return res.status(400).json({ error: "orgId required" });
    }

    const orgId = await ensureOrg(externalOrgId);

    const keys = await db.query.byokKeys.findMany({
      where: eq(byokKeys.orgId, orgId),
    });

    const maskedKeys = keys.map((key) => ({
      provider: key.provider,
      maskedKey: maskKey(decrypt(key.encryptedKey)),
      createdAt: key.createdAt,
      updatedAt: key.updatedAt,
    }));

    res.json({ keys: maskedKeys });
  } catch (error) {
    console.error("List keys error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

/**
 * POST /internal/keys
 * Add or update a BYOK key
 */
router.post("/keys", async (req: Request, res: Response) => {
  try {
    const parsed = CreateByokKeyRequestSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: "Invalid request", details: parsed.error.flatten() });
    }

    const { orgId: externalOrgId, provider, apiKey } = parsed.data;
    const orgId = await ensureOrg(externalOrgId);
    const encryptedKey = encrypt(apiKey);

    // Upsert
    const existing = await db.query.byokKeys.findFirst({
      where: and(eq(byokKeys.orgId, orgId), eq(byokKeys.provider, provider)),
    });

    if (existing) {
      await db
        .update(byokKeys)
        .set({ encryptedKey, updatedAt: new Date() })
        .where(eq(byokKeys.id, existing.id));
    } else {
      await db.insert(byokKeys).values({
        orgId,
        provider,
        encryptedKey,
      });
    }

    res.json({
      provider,
      maskedKey: maskKey(apiKey),
      message: `${provider} key saved successfully`,
    });
  } catch (error) {
    console.error("Set key error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

/**
 * DELETE /internal/keys/:provider
 * Delete a BYOK key
 */
router.delete("/keys/:provider", async (req: Request, res: Response) => {
  try {
    const { provider } = req.params;
    const parsed = DeleteByokKeyQuerySchema.safeParse(req.query);
    if (!parsed.success) {
      return res.status(400).json({ error: "orgId required" });
    }

    const { orgId: externalOrgId } = parsed.data;

    if (!VALID_PROVIDERS.includes(provider)) {
      return res.status(400).json({ error: "Invalid provider" });
    }

    const orgId = await ensureOrg(externalOrgId);

    await db
      .delete(byokKeys)
      .where(and(eq(byokKeys.orgId, orgId), eq(byokKeys.provider, provider)));

    res.json({
      provider,
      message: `${provider} key deleted successfully`,
    });
  } catch (error) {
    console.error("Delete key error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

/**
 * GET /internal/keys/:provider/decrypt
 * Get decrypted BYOK key (for internal service use)
 * Requires X-Caller-Service, X-Caller-Method, X-Caller-Path headers
 */
router.get("/keys/:provider/decrypt", async (req: Request, res: Response) => {
  try {
    const { provider } = req.params;
    const externalOrgId = req.query.orgId as string;

    if (!externalOrgId) {
      return res.status(400).json({ error: "orgId required" });
    }

    const caller = extractCallerHeaders(req);
    if (!caller) {
      return res.status(400).json({
        error: "Missing required headers: X-Caller-Service, X-Caller-Method, X-Caller-Path",
      });
    }

    const orgId = await ensureOrg(externalOrgId);

    const key = await db.query.byokKeys.findFirst({
      where: and(eq(byokKeys.orgId, orgId), eq(byokKeys.provider, provider)),
    });

    if (!key) {
      console.warn(`[KEY SERVICE] BYOK key not found: provider=${provider} orgId=${externalOrgId} caller=${caller.service}`);
      return res.status(404).json({ error: `BYOK key not found: no '${provider}' key configured for org '${externalOrgId}'` });
    }

    await recordProviderRequirement(caller, provider);

    res.json({
      provider,
      key: decrypt(key.encryptedKey),
    });
  } catch (error) {
    console.error("Decrypt BYOK key error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ==================== APP KEYS ====================

/**
 * GET /internal/app-keys
 * List app keys for an app (by appId)
 */
router.get("/app-keys", async (req: Request, res: Response) => {
  try {
    const { appId } = req.query;

    if (!appId || typeof appId !== "string") {
      return res.status(400).json({ error: "appId required" });
    }

    const keys = await db.query.appKeys.findMany({
      where: eq(appKeys.appId, appId),
    });

    const maskedKeys = keys.map((key) => ({
      provider: key.provider,
      maskedKey: maskKey(decrypt(key.encryptedKey)),
      createdAt: key.createdAt,
      updatedAt: key.updatedAt,
    }));

    res.json({ keys: maskedKeys });
  } catch (error) {
    console.error("List app keys error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

/**
 * POST /internal/app-keys
 * Add or update an app key
 */
router.post("/app-keys", async (req: Request, res: Response) => {
  try {
    const parsed = CreateAppKeyRequestSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: "Invalid request", details: parsed.error.flatten() });
    }

    const { appId, provider, apiKey } = parsed.data;
    const encryptedKey = encrypt(apiKey);

    // Upsert
    const existing = await db.query.appKeys.findFirst({
      where: and(eq(appKeys.appId, appId), eq(appKeys.provider, provider)),
    });

    if (existing) {
      await db
        .update(appKeys)
        .set({ encryptedKey, updatedAt: new Date() })
        .where(eq(appKeys.id, existing.id));
    } else {
      await db.insert(appKeys).values({
        appId,
        provider,
        encryptedKey,
      });
    }

    res.json({
      provider,
      maskedKey: maskKey(apiKey),
      message: `${provider} key saved successfully`,
    });
  } catch (error) {
    console.error("Set app key error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

/**
 * DELETE /internal/app-keys/:provider
 * Delete an app key
 */
router.delete("/app-keys/:provider", async (req: Request, res: Response) => {
  try {
    const { provider } = req.params;
    const parsed = DeleteAppKeyQuerySchema.safeParse(req.query);
    if (!parsed.success) {
      return res.status(400).json({ error: "appId required" });
    }

    const { appId } = parsed.data;

    await db
      .delete(appKeys)
      .where(and(eq(appKeys.appId, appId), eq(appKeys.provider, provider)));

    res.json({
      provider,
      message: `${provider} key deleted successfully`,
    });
  } catch (error) {
    console.error("Delete app key error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

/**
 * GET /internal/app-keys/:provider/decrypt
 * Get decrypted app key (for internal service use)
 * Requires X-Caller-Service, X-Caller-Method, X-Caller-Path headers
 */
router.get("/app-keys/:provider/decrypt", async (req: Request, res: Response) => {
  try {
    const { provider } = req.params;
    const appId = req.query.appId as string;

    if (!appId) {
      return res.status(400).json({ error: "appId required" });
    }

    const caller = extractCallerHeaders(req);
    if (!caller) {
      return res.status(400).json({
        error: "Missing required headers: X-Caller-Service, X-Caller-Method, X-Caller-Path",
      });
    }

    const key = await db.query.appKeys.findFirst({
      where: and(eq(appKeys.appId, appId), eq(appKeys.provider, provider)),
    });

    if (!key) {
      console.warn(`[KEY SERVICE] App key not found: provider=${provider} appId=${appId} caller=${caller.service}`);
      return res.status(404).json({ error: `App key not found: no '${provider}' key configured for app '${appId}'` });
    }

    await recordProviderRequirement(caller, provider);

    res.json({
      provider,
      key: decrypt(key.encryptedKey),
    });
  } catch (error) {
    console.error("Decrypt app key error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ==================== PLATFORM KEYS ====================

/**
 * GET /internal/platform-keys
 * List all platform keys
 */
router.get("/platform-keys", async (req: Request, res: Response) => {
  try {
    const keys = await db.query.platformKeys.findMany();

    const maskedKeys = keys.map((key) => ({
      provider: key.provider,
      maskedKey: maskKey(decrypt(key.encryptedKey)),
      createdAt: key.createdAt,
      updatedAt: key.updatedAt,
    }));

    res.json({ keys: maskedKeys });
  } catch (error) {
    console.error("List platform keys error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

/**
 * POST /internal/platform-keys
 * Add or update a platform key
 */
router.post("/platform-keys", async (req: Request, res: Response) => {
  try {
    const parsed = CreatePlatformKeyRequestSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: "Invalid request", details: parsed.error.flatten() });
    }

    const { provider, apiKey } = parsed.data;
    const encryptedKey = encrypt(apiKey);

    // Upsert
    const existing = await db.query.platformKeys.findFirst({
      where: eq(platformKeys.provider, provider),
    });

    if (existing) {
      await db
        .update(platformKeys)
        .set({ encryptedKey, updatedAt: new Date() })
        .where(eq(platformKeys.id, existing.id));
    } else {
      await db.insert(platformKeys).values({
        provider,
        encryptedKey,
      });
    }

    res.json({
      provider,
      maskedKey: maskKey(apiKey),
      message: `${provider} platform key saved successfully`,
    });
  } catch (error) {
    console.error("Set platform key error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

/**
 * DELETE /internal/platform-keys/:provider
 * Delete a platform key
 */
router.delete("/platform-keys/:provider", async (req: Request, res: Response) => {
  try {
    const { provider } = req.params;

    await db
      .delete(platformKeys)
      .where(eq(platformKeys.provider, provider));

    res.json({
      provider,
      message: `${provider} platform key deleted successfully`,
    });
  } catch (error) {
    console.error("Delete platform key error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

/**
 * GET /internal/platform-keys/:provider/decrypt
 * Get decrypted platform key (for internal service use)
 * Requires X-Caller-Service, X-Caller-Method, X-Caller-Path headers
 */
router.get("/platform-keys/:provider/decrypt", async (req: Request, res: Response) => {
  try {
    const { provider } = req.params;

    const caller = extractCallerHeaders(req);
    if (!caller) {
      return res.status(400).json({
        error: "Missing required headers: X-Caller-Service, X-Caller-Method, X-Caller-Path",
      });
    }

    const key = await db.query.platformKeys.findFirst({
      where: eq(platformKeys.provider, provider),
    });

    if (!key) {
      console.warn(`[KEY SERVICE] Platform key not found: provider=${provider} caller=${caller.service}`);
      return res.status(404).json({ error: `Platform key not found: no '${provider}' platform key configured` });
    }

    await recordProviderRequirement(caller, provider);

    res.json({
      provider,
      key: decrypt(key.encryptedKey),
    });
  } catch (error) {
    console.error("Decrypt platform key error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ==================== PROVIDER REQUIREMENTS ====================

/**
 * POST /internal/provider-requirements
 * Query which providers are needed for a set of endpoints
 */
router.post("/provider-requirements", async (req: Request, res: Response) => {
  try {
    const parsed = ProviderRequirementsRequestSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: "Invalid request", details: parsed.error.flatten() });
    }

    const { endpoints } = parsed.data;

    const results: Array<{
      service: string;
      method: string;
      path: string;
      provider: string;
    }> = [];

    for (const endpoint of endpoints) {
      const matches = await db.query.providerRequirements.findMany({
        where: and(
          eq(providerRequirements.service, endpoint.service.toLowerCase()),
          eq(providerRequirements.method, endpoint.method.toUpperCase()),
          eq(providerRequirements.path, endpoint.path)
        ),
      });

      for (const match of matches) {
        results.push({
          service: match.service,
          method: match.method,
          path: match.path,
          provider: match.provider,
        });
      }
    }

    const providers = [...new Set(results.map((r) => r.provider))].sort();

    res.json({ requirements: results, providers });
  } catch (error) {
    console.error("Provider requirements query error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

export default router;

// ==================== APP REGISTRATION ====================

/**
 * POST /internal/apps
 * Register a new app and get an App API Key.
 * Idempotent: if the app already exists, returns its prefix (not the full key).
 */
router.post("/apps", async (req: Request, res: Response) => {
  try {
    const parsed = RegisterAppRequestSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: "Invalid request", details: parsed.error.flatten() });
    }

    const { name } = parsed.data;

    // Check if app already exists
    const existing = await db.query.apps.findFirst({
      where: eq(apps.name, name),
    });

    if (existing) {
      return res.json({
        appId: existing.name,
        keyPrefix: existing.keyPrefix,
        created: false,
        message: "App already registered. API key was returned at creation time.",
      });
    }

    // Create new app with API key
    const rawKey = generateAppApiKey();
    const keyHash = hashApiKey(rawKey);
    const keyPrefix = getKeyPrefix(rawKey);

    const [app] = await db
      .insert(apps)
      .values({ name, keyHash, keyPrefix })
      .returning();

    res.json({
      appId: app.name,
      apiKey: rawKey,
      keyPrefix: app.keyPrefix,
      created: true,
      message: "App registered. Save this API key — it won't be shown again.",
    });
  } catch (error) {
    console.error("Register app error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});
