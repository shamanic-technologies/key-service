import { eq, and } from "drizzle-orm";
import { db } from "../db/index.js";
import { providerRequirements } from "../db/schema.js";
import { CallerInfo } from "./caller-headers.js";

/**
 * Record that a caller (service+method+path) requires a given provider.
 * Upserts: inserts if new, updates lastSeenAt if existing.
 */
export async function recordProviderRequirement(
  caller: CallerInfo,
  provider: string
): Promise<void> {
  const existing = await db.query.providerRequirements.findFirst({
    where: and(
      eq(providerRequirements.service, caller.service),
      eq(providerRequirements.method, caller.method),
      eq(providerRequirements.path, caller.path),
      eq(providerRequirements.provider, provider)
    ),
  });

  if (existing) {
    await db
      .update(providerRequirements)
      .set({ lastSeenAt: new Date() })
      .where(eq(providerRequirements.id, existing.id));
  } else {
    await db.insert(providerRequirements).values({
      service: caller.service,
      method: caller.method,
      path: caller.path,
      provider,
    });
  }
}
