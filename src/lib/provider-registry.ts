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
  await db
    .insert(providerRequirements)
    .values({
      service: caller.service,
      method: caller.method,
      path: caller.path,
      provider,
    })
    .onConflictDoUpdate({
      target: [
        providerRequirements.service,
        providerRequirements.method,
        providerRequirements.path,
        providerRequirements.provider,
      ],
      set: { lastSeenAt: new Date() },
    });
}
