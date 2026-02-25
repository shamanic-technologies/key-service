import { Request } from "express";

export interface CallerInfo {
  service: string;
  method: string;
  path: string;
}

/**
 * Extract and validate caller identification headers from a request.
 * Returns null if any required header is missing or empty.
 */
export function extractCallerHeaders(req: Request): CallerInfo | null {
  const service = req.headers["x-caller-service"];
  const method = req.headers["x-caller-method"];
  const path = req.headers["x-caller-path"];

  if (
    typeof service !== "string" || !service.trim() ||
    typeof method !== "string" || !method.trim() ||
    typeof path !== "string" || !path.trim()
  ) {
    return null;
  }

  return {
    service: service.trim().toLowerCase(),
    method: method.trim().toUpperCase(),
    path: path.trim(),
  };
}
