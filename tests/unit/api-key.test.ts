import { describe, it, expect } from "vitest";
import {
  generateApiKey,
  generateAppApiKey,
  isValidApiKeyFormat,
  isAppApiKey,
  isUserApiKey,
  hasValidPrefix,
  hashApiKey,
  getKeyPrefix,
} from "../../src/lib/api-key.js";

describe("api-key module", () => {
  describe("generateApiKey", () => {
    it("should generate keys with distrib.usr_ prefix", () => {
      const key = generateApiKey();
      expect(key).toMatch(/^distrib\.usr_[a-f0-9]{40}$/);
    });
  });

  describe("generateAppApiKey", () => {
    it("should generate keys with distrib.app_ prefix", () => {
      const key = generateAppApiKey();
      expect(key).toMatch(/^distrib\.app_[a-f0-9]{40}$/);
    });
  });

  describe("isValidApiKeyFormat", () => {
    it("should accept new distrib.usr_ format", () => {
      expect(isValidApiKeyFormat("distrib.usr_" + "a".repeat(40))).toBe(true);
    });

    it("should accept legacy mcpf_usr_ format", () => {
      expect(isValidApiKeyFormat("mcpf_usr_" + "a".repeat(40))).toBe(true);
    });

    it("should reject unknown prefix", () => {
      expect(isValidApiKeyFormat("unknown_" + "a".repeat(40))).toBe(false);
    });
  });

  describe("isAppApiKey", () => {
    it("should recognize new distrib.app_ keys", () => {
      expect(isAppApiKey("distrib.app_" + "a".repeat(40))).toBe(true);
    });

    it("should recognize legacy mcpf_app_ keys", () => {
      expect(isAppApiKey("mcpf_app_" + "a".repeat(40))).toBe(true);
    });

    it("should reject user keys", () => {
      expect(isAppApiKey("distrib.usr_" + "a".repeat(40))).toBe(false);
    });
  });

  describe("isUserApiKey", () => {
    it("should recognize new distrib.usr_ keys", () => {
      expect(isUserApiKey("distrib.usr_" + "a".repeat(40))).toBe(true);
    });

    it("should recognize legacy mcpf_usr_ keys", () => {
      expect(isUserApiKey("mcpf_usr_" + "a".repeat(40))).toBe(true);
    });

    it("should reject app keys", () => {
      expect(isUserApiKey("distrib.app_" + "a".repeat(40))).toBe(false);
    });
  });

  describe("hasValidPrefix", () => {
    it("should accept distrib. prefix", () => {
      expect(hasValidPrefix("distrib.usr_abc")).toBe(true);
      expect(hasValidPrefix("distrib.app_abc")).toBe(true);
    });

    it("should accept legacy mcpf_ prefix", () => {
      expect(hasValidPrefix("mcpf_usr_abc")).toBe(true);
      expect(hasValidPrefix("mcpf_app_abc")).toBe(true);
    });

    it("should reject unknown prefix", () => {
      expect(hasValidPrefix("unknown_abc")).toBe(false);
    });
  });

  describe("getKeyPrefix", () => {
    it("should return first 12 chars for new keys", () => {
      expect(getKeyPrefix("distrib.usr_" + "a".repeat(40))).toBe("distrib.usr_");
    });

    it("should return first 12 chars for legacy keys", () => {
      expect(getKeyPrefix("mcpf_usr_abc" + "d".repeat(37))).toBe("mcpf_usr_abc");
    });
  });

  describe("hashApiKey", () => {
    it("should produce consistent hash", () => {
      const key = "distrib.usr_" + "a".repeat(40);
      expect(hashApiKey(key)).toBe(hashApiKey(key));
    });

    it("should produce different hashes for different keys", () => {
      expect(hashApiKey("distrib.usr_" + "a".repeat(40))).not.toBe(
        hashApiKey("distrib.usr_" + "b".repeat(40))
      );
    });
  });
});
