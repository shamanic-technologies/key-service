/**
 * User auth key CRUD endpoints.
 * Mounted at /api-keys — requires identity headers.
 */

import { Router, Request, Response } from "express";
import { eq, and } from "drizzle-orm";
import { db } from "../db/index.js";
import { userAuthKeys } from "../db/schema.js";
import { generateApiKey, hashApiKey, getKeyPrefix } from "../lib/api-key.js";
import { encrypt, decrypt } from "../lib/crypto.js";
import { CreateUserAuthKeyRequestSchema } from "../schemas.js";

const router = Router();

/**
 * GET /api-keys
 * List user auth keys for the caller's org, optionally filtered by userId
 */
router.get("/", async (req: Request, res: Response) => {
  try {
    const { orgId } = req.identity!;

    const conditions = [eq(userAuthKeys.orgId, orgId)];
    const userId = req.query.userId;
    if (typeof userId === "string" && userId) {
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
 * POST /api-keys
 * Create a new user auth key
 */
router.post("/", async (req: Request, res: Response) => {
  try {
    const parsed = CreateUserAuthKeyRequestSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: "Invalid request", details: parsed.error.flatten() });
    }

    const { orgId } = req.identity!;
    const { userId, createdBy, name } = parsed.data;

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
 * DELETE /api-keys/:id
 * Delete a user auth key
 */
router.delete("/:id", async (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const { orgId } = req.identity!;

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
 * POST /api-keys/session
 * Get or create a "Default" user auth key for the org+user (from identity headers).
 */
router.post("/session", async (req: Request, res: Response) => {
  try {
    const { orgId, userId } = req.identity!;

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

export default router;
