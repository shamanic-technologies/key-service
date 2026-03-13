import { Request } from "express";

export interface TrackingInfo {
  campaignId: string;
  brandId: string;
  workflowName: string;
}

/**
 * Extract optional workflow tracking headers from a request.
 * Returns a partial TrackingInfo — only includes fields that are present and non-empty.
 * Returns null if no tracking headers are present.
 */
export function extractTrackingHeaders(req: Request): Partial<TrackingInfo> | null {
  const campaignId = req.headers["x-campaign-id"];
  const brandId = req.headers["x-brand-id"];
  const workflowName = req.headers["x-workflow-name"];

  const result: Partial<TrackingInfo> = {};

  if (typeof campaignId === "string" && campaignId.trim()) {
    result.campaignId = campaignId.trim();
  }
  if (typeof brandId === "string" && brandId.trim()) {
    result.brandId = brandId.trim();
  }
  if (typeof workflowName === "string" && workflowName.trim()) {
    result.workflowName = workflowName.trim();
  }

  return Object.keys(result).length > 0 ? result : null;
}
