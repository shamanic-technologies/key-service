import { eq } from "drizzle-orm";
import { db } from "../db/index.js";
import { orgs } from "../db/schema.js";

/**
 * Ensure org exists, creating if needed.
 * Returns the internal UUID for the org.
 */
export async function ensureOrg(orgId: string): Promise<string> {
  let org = await db.query.orgs.findFirst({
    where: eq(orgs.orgId, orgId),
  });

  if (!org) {
    const [newOrg] = await db
      .insert(orgs)
      .values({ orgId })
      .returning();
    org = newOrg;
  }

  return org.id;
}
