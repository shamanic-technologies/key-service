/**
 * Platform key CRUD endpoints.
 * Mounted at /platform-keys — NO identity headers needed (system-level, cold-start bootstrap).
 */

import { Router, Request, Response } from "express";
import { eq } from "drizzle-orm";
import { db } from "../db/index.js";
import { platformKeys, providers } from "../db/schema.js";
import { encrypt, decrypt, maskKey } from "../lib/crypto.js";
import { ensureProvider, getProviderByName } from "../lib/ensure-provider.js";
import { CreatePlatformKeyRequestSchema } from "../schemas.js";

const router = Router();

/**
 * GET /platform-keys
 * List all platform keys
 */
router.get("/", async (req: Request, res: Response) => {
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
 * POST /platform-keys
 * Add or update a platform key
 */
router.post("/", async (req: Request, res: Response) => {
  try {
    const parsed = CreatePlatformKeyRequestSchema.safeParse(req.body);
    if (!parsed.success) {
      console.warn(`[key-service] POST /platform-keys rejected: invalid request body`, parsed.error.flatten());
      return res.status(400).json({ error: "Invalid request", details: parsed.error.flatten() });
    }

    const { provider: providerName, apiKey } = parsed.data;
    console.log(`[key-service] POST /platform-keys: registering provider="${providerName}"`);

    const providerId = await ensureProvider(providerName);
    const encryptedKey = encrypt(apiKey);

    // Upsert
    const existing = await db.query.platformKeys.findFirst({
      where: eq(platformKeys.providerId, providerId),
    });

    if (existing) {
      const existingKey = decrypt(existing.encryptedKey);
      if (existingKey === apiKey) {
        console.log(`[key-service] Platform key unchanged, skipping: provider="${providerName}"`);
      } else {
        await db
          .update(platformKeys)
          .set({ encryptedKey, updatedAt: new Date() })
          .where(eq(platformKeys.id, existing.id));
        console.log(`[key-service] Platform key updated: provider="${providerName}" providerId=${providerId}`);
      }
    } else {
      await db.insert(platformKeys).values({
        providerId,
        encryptedKey,
      });
      console.log(`[key-service] Platform key created: provider="${providerName}" providerId=${providerId}`);
    }

    res.json({
      provider: providerName,
      maskedKey: maskKey(apiKey),
      message: `${providerName} platform key saved successfully`,
    });
  } catch (error) {
    console.error(`[key-service] POST /platform-keys FAILED for provider="${req.body?.provider ?? "unknown"}":`, error);
    res.status(500).json({ error: "Internal server error" });
  }
});

/**
 * DELETE /platform-keys/:provider
 * Delete a platform key
 */
router.delete("/:provider", async (req: Request, res: Response) => {
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

export default router;
