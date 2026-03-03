/**
 * Internal routes for service-to-service calls
 */

import { Router, Request, Response } from "express";
import { eq, and } from "drizzle-orm";
import { db } from "../db/index.js";
import { userAuthKeys, orgKeys, platformKeys, providers, providerRequirements } from "../db/schema.js";
import { generateApiKey, hashApiKey, getKeyPrefix } from "../lib/api-key.js";
import { encrypt, decrypt, maskKey } from "../lib/crypto.js";
import { ensureProvider, getProviderByName } from "../lib/ensure-provider.js";
import {
  CreateUserAuthKeyRequestSchema,
  DeleteUserAuthKeyRequestSchema,
  SessionKeyRequestSchema,
  CreateOrgKeyRequestSchema,
  DeleteOrgKeyQuerySchema,
  CreatePlatformKeyRequestSchema,
  ProviderRequirementsRequestSchema,
} from "../schemas.js";

const router = Router();

// ==================== USER AUTH KEYS ====================

/**
 * GET /internal/api-keys
 * List user auth keys for an org, optionally filtered by userId
 */
router.get("/api-keys", async (req: Request, res: Response) => {
  try {
    const { orgId, userId } = req.query;

    if (!orgId || typeof orgId !== "string") {
      return res.status(400).json({ error: "orgId required" });
    }

    const conditions = [eq(userAuthKeys.orgId, orgId)];
    if (userId && typeof userId === "string") {
      conditions.push(eq(userAuthKeys.userId, userId));
    }

    const keys = await db.query.userAuthKeys.findMany({
      where: and(...conditions),
    });

    res.json({
      keys: keys.map((k) => ({
        id: k.id,
        keyPrefix: k.keyPrefix,
        name: k.name,
        orgId: k.orgId,
        userId: k.userId,
        createdBy: k.createdBy,
        createdAt: k.createdAt,
        lastUsedAt: k.lastUsedAt,
      })),
    });
  } catch (error) {
    console.error("List user auth keys error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

/**
 * POST /internal/api-keys
 * Create a new user auth key
 */
router.post("/api-keys", async (req: Request, res: Response) => {
  try {
    const parsed = CreateUserAuthKeyRequestSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: "Invalid request", details: parsed.error.flatten() });
    }

    const { orgId, userId, createdBy, name } = parsed.data;

    const rawKey = generateApiKey();
    const keyHash = hashApiKey(rawKey);
    const keyPrefix = getKeyPrefix(rawKey);

    const [key] = await db
      .insert(userAuthKeys)
      .values({
        orgId,
        userId,
        createdBy,
        keyHash,
        keyPrefix,
        name,
      })
      .returning();

    res.json({
      id: key.id,
      key: rawKey,
      name: key.name,
      orgId: key.orgId,
      userId: key.userId,
      createdBy: key.createdBy,
      createdAt: key.createdAt,
    });
  } catch (error) {
    console.error("Create user auth key error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

/**
 * DELETE /internal/api-keys/:id
 * Delete a user auth key
 */
router.delete("/api-keys/:id", async (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const parsed = DeleteUserAuthKeyRequestSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: "orgId required" });
    }

    const { orgId } = parsed.data;

    const result = await db
      .delete(userAuthKeys)
      .where(and(eq(userAuthKeys.id, id), eq(userAuthKeys.orgId, orgId)))
      .returning();

    if (result.length === 0) {
      return res.status(404).json({ error: "User auth key not found" });
    }

    res.json({ message: "User auth key deleted successfully" });
  } catch (error) {
    console.error("Delete user auth key error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

/**
 * POST /internal/api-keys/session
 * Get or create a "Default" user auth key for the org+user.
 */
router.post("/api-keys/session", async (req: Request, res: Response) => {
  try {
    const parsed = SessionKeyRequestSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: "orgId and userId required" });
    }

    const { orgId, userId } = parsed.data;

    const existing = await db.query.userAuthKeys.findFirst({
      where: and(
        eq(userAuthKeys.orgId, orgId),
        eq(userAuthKeys.userId, userId),
        eq(userAuthKeys.name, "Default"),
      ),
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
      await db.delete(userAuthKeys).where(eq(userAuthKeys.id, existing.id));
    }

    // Create new Default key with encrypted storage
    const rawKey = generateApiKey();
    const keyHash = hashApiKey(rawKey);
    const keyPrefix = getKeyPrefix(rawKey);

    const [key] = await db
      .insert(userAuthKeys)
      .values({
        orgId,
        userId,
        createdBy: userId,
        keyHash,
        keyPrefix,
        encryptedKey: encrypt(rawKey),
        name: "Default",
      })
      .returning();

    res.json({
      id: key.id,
      key: rawKey,
      keyPrefix: key.keyPrefix,
      name: key.name,
    });
  } catch (error) {
    console.error("Session key error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ==================== ORG KEYS ====================

/**
 * GET /internal/keys
 * List org keys for an org
 */
router.get("/keys", async (req: Request, res: Response) => {
  try {
    const { orgId } = req.query;

    if (!orgId || typeof orgId !== "string") {
      return res.status(400).json({ error: "orgId required" });
    }

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
 * POST /internal/keys
 * Add or update an org key
 */
router.post("/keys", async (req: Request, res: Response) => {
  try {
    const parsed = CreateOrgKeyRequestSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: "Invalid request", details: parsed.error.flatten() });
    }

    const { orgId, provider: providerName, apiKey } = parsed.data;
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
 * DELETE /internal/keys/:provider
 * Delete an org key
 */
router.delete("/keys/:provider", async (req: Request, res: Response) => {
  try {
    const { provider: providerName } = req.params;
    const parsed = DeleteOrgKeyQuerySchema.safeParse(req.query);
    if (!parsed.success) {
      return res.status(400).json({ error: "orgId required" });
    }

    const { orgId } = parsed.data;

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

// ==================== PLATFORM KEYS ====================

/**
 * GET /internal/platform-keys
 * List all platform keys
 */
router.get("/platform-keys", async (req: Request, res: Response) => {
  try {
    const keys = await db.query.platformKeys.findMany();

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

    const { provider: providerName, apiKey } = parsed.data;
    const providerId = await ensureProvider(providerName);
    const encryptedKey = encrypt(apiKey);

    // Upsert
    const existing = await db.query.platformKeys.findFirst({
      where: eq(platformKeys.providerId, providerId),
    });

    if (existing) {
      await db
        .update(platformKeys)
        .set({ encryptedKey, updatedAt: new Date() })
        .where(eq(platformKeys.id, existing.id));
    } else {
      await db.insert(platformKeys).values({
        providerId,
        encryptedKey,
      });
    }

    res.json({
      provider: providerName,
      maskedKey: maskKey(apiKey),
      message: `${providerName} platform key saved successfully`,
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
    const { provider: providerName } = req.params;

    const provider = await getProviderByName(providerName);
    if (provider) {
      await db
        .delete(platformKeys)
        .where(eq(platformKeys.providerId, provider.id));
    }

    res.json({
      provider: providerName,
      message: `${providerName} platform key deleted successfully`,
    });
  } catch (error) {
    console.error("Delete platform key error:", error);
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

    const providerList = [...new Set(results.map((r) => r.provider))].sort();

    res.json({ requirements: results, providers: providerList });
  } catch (error) {
    console.error("Provider requirements query error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

export default router;
