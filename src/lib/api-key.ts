import crypto from "crypto";

/**
 * Generate a new user API key in format: mcpf_usr_xxxxxxxxxxxxxxxxxxxx
 */
export function generateApiKey(): string {
  const randomBytes = crypto.randomBytes(20);
  const hex = randomBytes.toString("hex");
  return `mcpf_usr_${hex}`;
}

/**
 * Generate a new App API key in format: mcpf_app_xxxxxxxxxxxxxxxxxxxx
 */
export function generateAppApiKey(): string {
  const randomBytes = crypto.randomBytes(20);
  const hex = randomBytes.toString("hex");
  return `mcpf_app_${hex}`;
}

/**
 * Validate user API key format
 */
export function isValidApiKeyFormat(key: string): boolean {
  return /^mcpf_usr_[a-f0-9]{40}$/.test(key);
}

/**
 * Check if key is an app API key
 */
export function isAppApiKey(key: string): boolean {
  return key.startsWith("mcpf_app_");
}

/**
 * Check if key is a user API key
 */
export function isUserApiKey(key: string): boolean {
  return key.startsWith("mcpf_usr_");
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
  return key.slice(0, 12); // "mcpf_xxxx" first 12 chars
}
