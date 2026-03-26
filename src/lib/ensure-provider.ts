import { eq } from "drizzle-orm";
import { db } from "../db/index.js";
import { providers } from "../db/schema.js";

/**
 * Get or create a provider by name.
 * Returns the provider's UUID.
 */
export async function ensureProvider(name: string): Promise<string> {
  let provider = await db.query.providers.findFirst({
    where: eq(providers.name, name),
  });

  if (!provider) {
    const [created] = await db
      .insert(providers)
      .values({ name })
      .returning();
    provider = created;
    console.log(`[key-service] New provider created: name="${name}" id=${provider.id}`);
  }

  return provider.id;
}

/**
 * Get a provider by name (lookup only, no auto-create).
 */
export async function getProviderByName(name: string) {
  return db.query.providers.findFirst({
    where: eq(providers.name, name),
  });
}
