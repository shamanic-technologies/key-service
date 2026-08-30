import { describe, it, expect } from "vitest";
import { encrypt, decrypt, maskKey } from "../../src/lib/crypto.js";
import { serializeSecret, deserializeSecret, maskValue } from "../../src/lib/secret-codec.js";

describe("secret-codec — JSON-object secret values", () => {
  it("round-trips a string value as a string", () => {
    const original = "sk-ant-plain-string";
    const blob = encrypt(serializeSecret(original));
    const out = deserializeSecret(decrypt(blob));
    expect(out).toBe(original);
  });

  it("round-trips a {username,password} object as an object", () => {
    const original = { username: "alice@x.com", password: "topsecret" };
    const blob = encrypt(serializeSecret(original));
    const out = deserializeSecret(decrypt(blob));
    expect(out).toEqual(original);
  });

  it("maskValue hides password and partially masks username", () => {
    const masked = maskValue({ username: "alice@example.com", password: "topsecret" });
    expect(typeof masked).toBe("string");
    expect(masked).not.toContain("topsecret");
    expect(masked).toContain("alic");
  });

  it("maskValue on a string forwards to maskKey", () => {
    expect(maskValue("sk-1234567890abcdef")).toBe(maskKey("sk-1234567890abcdef"));
  });
});
