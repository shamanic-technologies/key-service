import { eq, and } from "drizzle-orm";
import { db } from "../db/index.js";
import { orgProviderKeySources } from "../db/schema.js";
import { getProviderByName } from "./ensure-provider.js";

export interface KeySourcePreference {
  provider: string;
  orgId: string;
  keySource: "org" | "platform";
  isDefault: boolean;
}

/**
 * An org's key-source preference for a provider. Keyed on the org alone: the
 * preference belongs to the org, so no user is needed to read it. No stored
 * preference (or a provider never seen) = "platform", isDefault=true.
 */
export async function readKeySourcePreference(
  orgId: string,
  providerName: string
): Promise<KeySourcePreference> {
  const provider = await getProviderByName(providerName);
  if (!provider) {
    return { provider: providerName, orgId, keySource: "platform", isDefault: true };
  }

  const pref = await db.query.orgProviderKeySources.findFirst({
    where: and(
      eq(orgProviderKeySources.orgId, orgId),
      eq(orgProviderKeySources.providerId, provider.id),
    ),
  });

  return {
    provider: providerName,
    orgId,
    keySource: (pref?.keySource as "org" | "platform") ?? "platform",
    isDefault: !pref,
  };
}
