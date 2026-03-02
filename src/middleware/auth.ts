import { Request, Response, NextFunction } from "express";

/**
 * Require x-org-id and x-user-id identity headers.
 * Applied to all protected routes except /validate (chicken-and-egg: validate discovers identity from key).
 */
export function requireIdentityHeaders(
  req: Request,
  res: Response,
  next: NextFunction
) {
  const orgId = req.headers["x-org-id"];
  const userId = req.headers["x-user-id"];

  if (typeof orgId !== "string" || !orgId.trim()) {
    return res.status(400).json({ error: "Missing required header: x-org-id" });
  }
  if (typeof userId !== "string" || !userId.trim()) {
    return res.status(400).json({ error: "Missing required header: x-user-id" });
  }

  next();
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
  const serviceKey = process.env.KEY_SERVICE_API_KEY?.trim();

  if (!serviceKey) {
    console.error("[KEY SERVICE] KEY_SERVICE_API_KEY not configured");
    return res.status(500).json({ error: "Service not configured" });
  }

  const authHeader = req.headers["x-api-key"] || req.headers["authorization"];
  const providedKey = typeof authHeader === "string"
    ? authHeader.replace(/^Bearer\s+/i, "").trim()
    : null;

  if (!providedKey || providedKey !== serviceKey) {
    const headerName = req.headers["x-api-key"] ? "x-api-key" : req.headers["authorization"] ? "authorization" : "none";
    const headerType = typeof authHeader;
    const keyPreview = providedKey ? `${providedKey.slice(0, 4)}...` : "null";
    const expectedPreview = `${serviceKey.slice(0, 4)}...`;
    console.warn(
      `[KEY SERVICE] auth REJECTED: method=${req.method} path=${req.path} header=${headerName} headerType=${headerType} provided=${keyPreview} expected=${expectedPreview}`
    );
    return res.status(401).json({ error: "Invalid service key" });
  }

  next();
}
