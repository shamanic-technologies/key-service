/**
 * Internal routes for service-to-service calls
 * No auth needed - Railway private network
 */

import { Router, Request, Response } from "express";
import { eq, and } from "drizzle-orm";
import { db } from "../db/index.js";
import { apiKeys, appKeys, byokKeys, orgs, users } from "../db/schema.js";
import { generateApiKey, hashApiKey, getKeyPrefix } from "../lib/api-key.js";
import { encrypt, decrypt, maskKey } from "../lib/crypto.js";
import {
  CreateApiKeyRequestSchema,
  DeleteApiKeyRequestSchema,
  SessionApiKeyRequestSchema,
  CreateByokKeyRequestSchema,
  DeleteByokKeyQuerySchema,
  CreateAppKeyRequestSchema,
  DeleteAppKeyQuerySchema,
} from "../schemas.js";

const router = Router();

const VALID_PROVIDERS = ["apollo", "anthropic"];

// No auth middleware needed - Railway private network

/**
 * Ensure org exists, creating if needed
 */
async function ensureOrg(clerkOrgId: string): Promise<string> {
  let org = await db.query.orgs.findFirst({
    where: eq(orgs.clerkOrgId, clerkOrgId),
  });

  if (!org) {
    const [newOrg] = await db
      .insert(orgs)
      .values({ clerkOrgId })
      .returning();
    org = newOrg;
  }

  return org.id;
}

// ==================== API KEYS ====================

/**
 * GET /internal/api-keys
 * List API keys for an org (by clerkOrgId)
 */
router.get("/api-keys", async (req: Request, res: Response) => {
  try {
    const { clerkOrgId } = req.query;

    if (!clerkOrgId || typeof clerkOrgId !== "string") {
      return res.status(400).json({ error: "clerkOrgId required" });
    }

    const orgId = await ensureOrg(clerkOrgId);

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

    const { clerkOrgId, name } = parsed.data;
    const orgId = await ensureOrg(clerkOrgId);

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
      return res.status(400).json({ error: "clerkOrgId required" });
    }

    const { clerkOrgId } = parsed.data;
    const orgId = await ensureOrg(clerkOrgId);

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
      return res.status(400).json({ error: "clerkOrgId required" });
    }

    const { clerkOrgId } = parsed.data;
    const orgId = await ensureOrg(clerkOrgId);

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
    const { clerkOrgId } = req.query;

    if (!clerkOrgId || typeof clerkOrgId !== "string") {
      return res.status(400).json({ error: "clerkOrgId required" });
    }

    const orgId = await ensureOrg(clerkOrgId);

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

    const { clerkOrgId, provider, apiKey } = parsed.data;
    const orgId = await ensureOrg(clerkOrgId);
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
      return res.status(400).json({ error: "clerkOrgId required" });
    }

    const { clerkOrgId } = parsed.data;

    if (!VALID_PROVIDERS.includes(provider)) {
      return res.status(400).json({ error: "Invalid provider" });
    }

    const orgId = await ensureOrg(clerkOrgId);

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
 * Called by apollo-service via Railway private network
 */
router.get("/keys/:provider/decrypt", async (req: Request, res: Response) => {
  try {
    const { provider } = req.params;
    const clerkOrgId = req.query.clerkOrgId as string;

    if (!clerkOrgId) {
      return res.status(400).json({ error: "clerkOrgId required" });
    }

    const orgId = await ensureOrg(clerkOrgId);

    const key = await db.query.byokKeys.findFirst({
      where: and(eq(byokKeys.orgId, orgId), eq(byokKeys.provider, provider)),
    });

    if (!key) {
      return res.status(404).json({ error: `${provider} key not configured` });
    }

    res.json({
      provider,
      key: decrypt(key.encryptedKey),
    });
  } catch (error) {
    console.error("Decrypt key error:", error);
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
 */
router.get("/app-keys/:provider/decrypt", async (req: Request, res: Response) => {
  try {
    const { provider } = req.params;
    const appId = req.query.appId as string;

    if (!appId) {
      return res.status(400).json({ error: "appId required" });
    }

    const key = await db.query.appKeys.findFirst({
      where: and(eq(appKeys.appId, appId), eq(appKeys.provider, provider)),
    });

    if (!key) {
      return res.status(404).json({ error: `${provider} key not configured for app ${appId}` });
    }

    res.json({
      provider,
      key: decrypt(key.encryptedKey),
    });
  } catch (error) {
    console.error("Decrypt app key error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

export default router;
