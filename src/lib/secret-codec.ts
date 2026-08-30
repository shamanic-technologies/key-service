import { z } from "zod";
import { maskKey } from "./crypto.js";

/**
 * Featured.com Premium API uses username + password instead of a single API key.
 * Stored as a single JSON-stringified blob in the existing encryptedKey column.
 */
export const FeaturedCredentialsSchema = z.object({
  username: z.string().min(1),
  password: z.string().min(1),
});

export type FeaturedCredentials = z.infer<typeof FeaturedCredentialsSchema>;

/** A secret value: either a plain string (most providers) or a structured object (featured). */
export const SecretValueSchema = z.union([
  z.string().min(1),
  FeaturedCredentialsSchema,
]);

export type SecretValue = z.infer<typeof SecretValueSchema>;

/**
 * Serialize a secret to a string suitable for encrypt(). Objects are JSON-stringified;
 * strings pass through unchanged.
 */
export function serializeSecret(value: SecretValue): string {
  if (typeof value === "string") return value;
  return JSON.stringify(value);
}

/**
 * Inverse of serializeSecret. Detects JSON-object payloads by leading `{`; falls back
 * to the raw string when parsing fails or the parsed value is not an object.
 */
export function deserializeSecret(plaintext: string): SecretValue {
  if (plaintext.length === 0 || plaintext[0] !== "{") return plaintext;
  try {
    const parsed = JSON.parse(plaintext);
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      return parsed as SecretValue;
    }
    return plaintext;
  } catch {
    return plaintext;
  }
}

/** Display-friendly redaction. Always returns a string for list views. */
export function maskValue(value: SecretValue): string {
  if (typeof value === "string") return maskKey(value);
  return `${maskKey(value.username)} / ••••••••`;
}
