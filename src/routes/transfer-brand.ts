/**
 * POST /internal/transfer-brand — the fleet brand-transfer contract.
 * Mounted at /internal/transfer-brand, service-key auth only.
 *
 * brand-service discovers every service registering this path and calls each
 * one when a brand moves from one org to another. key-service's share of a
 * brand is its brand-scoped credentials (brand_keys): they move to the target
 * org (and to targetBrandId when given), so a service resolving the brand's
 * key under the target org keeps working, and the source org holds none of
 * them afterwards.
 *
 * Org-wide credentials (org_keys), key-source preferences and user auth keys
 * belong to the org, not to any one brand, and are never touched here.
 *
 * Collision: when the target org already holds a credential for the same
 * brand and provider, the target's row wins (it was stored there on purpose)
 * and the source row is removed, so the source still ends up empty.
 *
 * Idempotent: a second call finds nothing left under the source and moves 0.
 * Never logs or returns a secret — only counts and ids.
 */

import { Router, Request, Response } from "express";
import { and, eq, inArray } from "drizzle-orm";
import { db } from "../db/index.js";
import { brandKeys, providers } from "../db/schema.js";
import { recordSecretEvent } from "../lib/audit.js";
import { TransferBrandRequestSchema } from "../schemas.js";

const router = Router();

router.post("/", async (req: Request, res: Response) => {
  try {
    const parsed = TransferBrandRequestSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: "Invalid request", details: parsed.error.flatten() });
    }
    const { sourceBrandId, sourceOrgId, targetOrgId, targetBrandId } = parsed.data;
    const destBrandId = targetBrandId ?? sourceBrandId;

    const result = await db.transaction(async (tx) => {
      // Rows of this brand under the source org, plus any left under the target
      // org with the old brand id by an earlier call made without targetBrandId.
      const candidates = await tx
        .select({ id: brandKeys.id, orgId: brandKeys.orgId, brandId: brandKeys.brandId, providerId: brandKeys.providerId })
        .from(brandKeys)
        .where(
          and(
            eq(brandKeys.brandId, sourceBrandId),
            inArray(brandKeys.orgId, [sourceOrgId, targetOrgId])
          )
        );
      const toMove = candidates.filter((r) => !(r.orgId === targetOrgId && r.brandId === destBrandId));

      let moved = 0;
      let superseded = 0;
      const touched: { providerId: string; action: "update" | "delete"; orgId: string }[] = [];
      for (const row of toMove) {
        const existing = await tx
          .select({ id: brandKeys.id })
          .from(brandKeys)
          .where(
            and(
              eq(brandKeys.orgId, targetOrgId),
              eq(brandKeys.brandId, destBrandId),
              eq(brandKeys.providerId, row.providerId)
            )
          );
        if (existing.length > 0) {
          await tx.delete(brandKeys).where(eq(brandKeys.id, row.id));
          touched.push({ providerId: row.providerId, action: "delete", orgId: row.orgId });
          superseded++;
        } else {
          await tx
            .update(brandKeys)
            .set({ orgId: targetOrgId, brandId: destBrandId, updatedAt: new Date() })
            .where(eq(brandKeys.id, row.id));
          touched.push({ providerId: row.providerId, action: "update", orgId: targetOrgId });
          moved++;
        }
      }
      return { moved, superseded, touched };
    });

    const names = new Map((await db.select({ id: providers.id, name: providers.name }).from(providers)).map((p) => [p.id, p.name]));
    for (const t of result.touched) {
      await recordSecretEvent(req, { action: t.action, grain: "brand", provider: names.get(t.providerId) ?? t.providerId, orgId: t.orgId, brandId: t.action === "update" ? destBrandId : sourceBrandId, outcome: "success" });
    }

    console.log(
      `[key-service] transfer-brand: brand_keys moved=${result.moved} superseded=${result.superseded} ` +
        `(sourceBrandId=${sourceBrandId}, targetBrandId=${targetBrandId ?? "none"}, ${sourceOrgId} -> ${targetOrgId})`
    );

    res.json({
      updatedTables: [{ tableName: "brand_keys", count: result.moved + result.superseded }],
    });
  } catch (error) {
    console.error("[key-service] transfer-brand error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

export default router;
