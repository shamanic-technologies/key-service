import { Request, Response, NextFunction } from "express";

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
