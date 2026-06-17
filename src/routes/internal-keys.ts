/**
 * Internal key-service-owned org credential teardown endpoints.
 * Mounted at /internal/keys - service-key auth only.
 */

import { Router, Request, Response } from "express";
import { eq } from "drizzle-orm";
import { z } from "zod";
import { db } from "../db/index.js";
import { orgKeys, orgProviderKeySources, userAuthKeys } from "../db/schema.js";

const router = Router();
const OrgIdParamSchema = z.string().uuid();

/**
 * DELETE /internal/keys/by-org/:orgId
 * Delete all key-service-owned org credential material for an internal org UUID.
 */
router.delete("/by-org/:orgId", async (req: Request, res: Response) => {
  try {
    const parsedOrgId = OrgIdParamSchema.safeParse(req.params.orgId);
    if (!parsedOrgId.success) {
      return res.status(400).json({ error: "Invalid orgId: expected internal org UUID" });
    }
    const orgId = parsedOrgId.data;

    const deleted = await db.transaction(async (tx) => {
      const deletedKeySources = await tx
        .delete(orgProviderKeySources)
        .where(eq(orgProviderKeySources.orgId, orgId))
        .returning({ id: orgProviderKeySources.id });

      const deletedOrgKeys = await tx
        .delete(orgKeys)
        .where(eq(orgKeys.orgId, orgId))
        .returning({ id: orgKeys.id });

      const deletedApiKeys = await tx
        .delete(userAuthKeys)
        .where(eq(userAuthKeys.orgId, orgId))
        .returning({ id: userAuthKeys.id });

      return {
        orgKeys: deletedOrgKeys.length,
        keySources: deletedKeySources.length,
        apiKeys: deletedApiKeys.length,
      };
    });

    res.json({
      orgId,
      deleted,
      message: "Org credential material deleted successfully",
    });
  } catch (error) {
    console.error("Delete org credential material error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

export default router;
