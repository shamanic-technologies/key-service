/**
 * Internal org-keyed endpoints for server-to-server callers with no end user
 * (webhooks, pollers, teardown cascades).
 * Mounted at /internal/keys - service-key auth only.
 */

import { Router, Request, Response } from "express";
import { eq, inArray } from "drizzle-orm";
import { z } from "zod";
import { db } from "../db/index.js";
import { orgKeys, orgProviderKeySources, userAuthKeys, providers } from "../db/schema.js";
import { readKeySourcePreference } from "../lib/key-source.js";
import { recordSecretEvent } from "../lib/audit.js";

const router = Router();

async function providerNames(ids: string[]): Promise<string[]> {
  if (ids.length === 0) return [];
  const rows = await db.select({ name: providers.name }).from(providers).where(inArray(providers.id, ids));
  return rows.map((r) => r.name);
}
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
        .returning({ id: orgKeys.id, providerId: orgKeys.providerId });

      const deletedApiKeys = await tx
        .delete(userAuthKeys)
        .where(eq(userAuthKeys.orgId, orgId))
        .returning({ id: userAuthKeys.id });

      return {
        orgKeys: deletedOrgKeys.length,
        keySources: deletedKeySources.length,
        apiKeys: deletedApiKeys.length,
        deletedProviderIds: deletedOrgKeys.map((r) => r.providerId),
      };
    });

    for (const provider of await providerNames(deleted.deletedProviderIds)) {
      await recordSecretEvent(req, { action: "delete", grain: "org", provider, orgId, outcome: "success" });
    }

    res.json({
      orgId,
      deleted: { orgKeys: deleted.orgKeys, keySources: deleted.keySources, apiKeys: deleted.apiKeys },
      message: "Org credential material deleted successfully",
    });
  } catch (error) {
    console.error("Delete org credential material error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

/**
 * GET /internal/keys/by-org/:orgId/:provider/source
 * Read an org's key-source preference with no user: for machine-triggered
 * callers (a Stripe webhook, a poller) where no end user exists. Same body as
 * GET /keys/:provider/source.
 */
router.get("/by-org/:orgId/:provider/source", async (req: Request, res: Response) => {
  try {
    const parsedOrgId = OrgIdParamSchema.safeParse(req.params.orgId);
    if (!parsedOrgId.success) {
      return res.status(400).json({ error: "Invalid orgId: expected internal org UUID" });
    }
    res.json(await readKeySourcePreference(parsedOrgId.data, req.params.provider));
  } catch (error) {
    console.error("Internal get key source error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

export default router;
