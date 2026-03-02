import crypto from "crypto";

/**
 * Generate a new user API key in format: distrib.usr_xxxxxxxxxxxxxxxxxxxx
 */
export function generateApiKey(): string {
  const randomBytes = crypto.randomBytes(20);
  const hex = randomBytes.toString("hex");
  return `distrib.usr_${hex}`;
}

/**
 * Validate user API key format (accepts both legacy mcpf_ and new distrib. prefix)
 */
export function isValidApiKeyFormat(key: string): boolean {
  return /^(distrib\.usr_|mcpf_usr_)[a-f0-9]{40}$/.test(key);
}

/**
 * Check if key is a user API key (accepts both legacy mcpf_ and new distrib. prefix)
 */
export function isUserApiKey(key: string): boolean {
  return key.startsWith("distrib.usr_") || key.startsWith("mcpf_usr_");
}

/**
 * Check if key uses a recognized prefix (user keys only)
 */
export function hasValidPrefix(key: string): boolean {
  return isUserApiKey(key);
}

/**
 * Hash API key for storage (we never store raw keys)
 */
export function hashApiKey(key: string): string {
  return crypto.createHash("sha256").update(key).digest("hex");
}

/**
 * Get the prefix of an API key for display
 */
export function getKeyPrefix(key: string): string {
  return key.slice(0, 12); // first 12 chars for display
}
