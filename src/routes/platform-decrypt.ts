/**
 * Platform key decrypt endpoint.
 * Mounted at /keys/platform — no identity headers needed (platform keys are global).
 */

import { Router, Request, Response } from "express";
import { eq } from "drizzle-orm";
import { db } from "../db/index.js";
import { platformKeys } from "../db/schema.js";
import { decrypt } from "../lib/crypto.js";
import { extractCallerHeaders } from "../lib/caller-headers.js";
import { recordProviderRequirement } from "../lib/provider-registry.js";
import { getProviderByName } from "../lib/ensure-provider.js";

const router = Router();

/**
 * GET /keys/platform/:provider/decrypt
 * Get decrypted platform key directly — no auto-resolve, no orgId/userId needed
 */
router.get("/:provider/decrypt", async (req: Request, res: Response) => {
  try {
    const { provider: providerName } = req.params;

    const caller = extractCallerHeaders(req);
    if (!caller) {
      return res.status(400).json({
        error: "Missing required headers: X-Caller-Service, X-Caller-Method, X-Caller-Path",
      });
    }

    const provider = await getProviderByName(providerName);
    if (!provider) {
      console.warn(`[key-service] GET /keys/platform/${providerName}/decrypt → 404: provider not found in providers table`);
      return res.status(404).json({ error: `Platform key not found: no '${providerName}' platform key configured` });
    }

    const key = await db.query.platformKeys.findFirst({
      where: eq(platformKeys.providerId, provider.id),
    });

    if (!key) {
      console.warn(`[key-service] GET /keys/platform/${providerName}/decrypt → 404: provider exists but no platform key row`);
      return res.status(404).json({ error: `Platform key not found: no '${providerName}' platform key configured` });
    }

    await recordProviderRequirement(caller, providerName);

    res.json({
      provider: providerName,
      key: decrypt(key.encryptedKey),
    });
  } catch (error) {
    console.error("Decrypt platform key error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

export default router;
