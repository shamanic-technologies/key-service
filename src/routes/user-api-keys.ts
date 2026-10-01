/**
 * A user's own API keys, across every org they hold one in.
 * Mounted at /internal/user-api-keys — service-key auth only, no x-org-id.
 *
 * A user API key (`distrib.usr_*`) belongs to its USER, whatever org was active
 * when it was minted (owner decision 2026-10-01). Listing and revoking are
 * therefore keyed on the user UUID, never on an org: the caller (api-service)
 * passes the user it authenticated, never a value taken from client input.
 * Another user's key is invisible here — a DELETE of it is a 404, the same
 * answer as a key that does not exist, so a revoke cannot probe for ids.
 */

import { Router, Request, Response } from "express";
import { eq, and, desc } from "drizzle-orm";
import { z } from "zod";
import { db } from "../db/index.js";
import { userAuthKeys } from "../db/schema.js";

const router = Router();
const UuidSchema = z.string().uuid();

/**
 * GET /internal/user-api-keys/by-user/:userId
 * Every key owned by this user, in every org, newest first.
 */
router.get("/by-user/:userId", async (req: Request, res: Response) => {
  try {
    const parsedUserId = UuidSchema.safeParse(req.params.userId);
    if (!parsedUserId.success) {
      return res.status(400).json({ error: "Invalid userId: expected internal user UUID" });
    }

    const keys = await db.query.userAuthKeys.findMany({
      where: eq(userAuthKeys.userId, parsedUserId.data),
      orderBy: [desc(userAuthKeys.createdAt)],
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
    console.error("List user's API keys across orgs error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

/**
 * DELETE /internal/user-api-keys/by-user/:userId/:id
 * Revoke one key, only if this user owns it (any org).
 */
router.delete("/by-user/:userId/:id", async (req: Request, res: Response) => {
  try {
    const parsedUserId = UuidSchema.safeParse(req.params.userId);
    if (!parsedUserId.success) {
      return res.status(400).json({ error: "Invalid userId: expected internal user UUID" });
    }
    const parsedId = UuidSchema.safeParse(req.params.id);
    if (!parsedId.success) {
      return res.status(404).json({ error: "User auth key not found" });
    }

    const result = await db
      .delete(userAuthKeys)
      .where(and(eq(userAuthKeys.id, parsedId.data), eq(userAuthKeys.userId, parsedUserId.data)))
      .returning({ id: userAuthKeys.id, orgId: userAuthKeys.orgId });

    if (result.length === 0) {
      return res.status(404).json({ error: "User auth key not found" });
    }

    res.json({ message: "User auth key deleted successfully", id: result[0].id, orgId: result[0].orgId });
  } catch (error) {
    console.error("Revoke user's API key error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

export default router;
