/**
 * Provider requirements query endpoint.
 * Mounted at /provider-requirements — NO identity headers needed.
 */

import { Router, Request, Response } from "express";
import { eq, and } from "drizzle-orm";
import { db } from "../db/index.js";
import { providerRequirements } from "../db/schema.js";
import { ProviderRequirementsRequestSchema } from "../schemas.js";

const router = Router();

/**
 * POST /provider-requirements
 * Query which providers are needed for a set of endpoints
 */
router.post("/", async (req: Request, res: Response) => {
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
