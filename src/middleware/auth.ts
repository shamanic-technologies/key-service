import { Request, Response, NextFunction } from "express";
import { eq } from "drizzle-orm";
import { db } from "../db/index.js";
import { apiKeys, apps } from "../db/schema.js";
import { hashApiKey, isAppApiKey } from "../lib/api-key.js";

export interface AuthenticatedRequest extends Request {
  orgId?: string;
  appId?: string;
  authType?: "user_key" | "app_key";
}

/**
 * Authenticate via service API key (for service-to-service calls)
 * Checks KEY_SERVICE_API_KEY environment variable
 */
export function serviceKeyAuth(
  req: Request,
  res: Response,
  next: NextFunction
) {
  const serviceKey = process.env.KEY_SERVICE_API_KEY;

  if (!serviceKey) {
    console.error("[KEY SERVICE] KEY_SERVICE_API_KEY not configured");
    return res.status(500).json({ error: "Service not configured" });
  }

  const authHeader = req.headers["x-api-key"] || req.headers["authorization"];
  const providedKey = typeof authHeader === "string"
    ? authHeader.replace(/^Bearer\s+/i, "")
    : null;

  if (!providedKey || providedKey !== serviceKey) {
    console.warn(`[KEY SERVICE] auth REJECTED: method=${req.method} path=${req.path}`);
    return res.status(401).json({ error: "Invalid service key" });
  }

  next();
}

/**
 * Authenticate via API key (user key or app key)
 * - User keys (mcpf_*): resolve to orgId
 * - App keys (mcpf_app_*): resolve to appId
 */
export async function apiKeyAuth(
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
) {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith("Bearer ")) {
      return res.status(401).json({ error: "Missing authorization header" });
    }

    const key = authHeader.slice(7);

    if (!key.startsWith("mcpf_")) {
      return res.status(401).json({ error: "Invalid API key format" });
    }

    const keyHash = hashApiKey(key);

    // App keys: look up in apps table
    if (isAppApiKey(key)) {
      const app = await db.query.apps.findFirst({
        where: eq(apps.keyHash, keyHash),
      });

      if (!app) {
        return res.status(401).json({ error: "Invalid API key" });
      }

      req.appId = app.name;
      req.authType = "app_key";
      return next();
    }

    // User keys: look up in apiKeys table
    const apiKey = await db.query.apiKeys.findFirst({
      where: eq(apiKeys.keyHash, keyHash),
    });

    if (!apiKey) {
      return res.status(401).json({ error: "Invalid API key" });
    }

    // Update last used
    await db
      .update(apiKeys)
      .set({ lastUsedAt: new Date() })
      .where(eq(apiKeys.id, apiKey.id));

    req.orgId = apiKey.orgId;
    req.authType = "user_key";
    next();
  } catch (error) {
    console.error("API key auth error:", error);
    return res.status(401).json({ error: "Authentication failed" });
  }
}
