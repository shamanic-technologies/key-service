declare namespace Express {
  interface Request {
    identity?: {
      orgId: string;
      userId: string;
    };
    tracking?: {
      campaignId?: string;
      brandId?: string;
      workflowSlug?: string;
      featureSlug?: string;
    } | null;
  }
}
