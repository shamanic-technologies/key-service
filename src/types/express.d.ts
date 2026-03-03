declare namespace Express {
  interface Request {
    identity?: {
      orgId: string;
      userId: string;
    };
  }
}
