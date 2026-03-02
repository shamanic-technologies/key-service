ALTER TABLE "byok_keys" RENAME TO "org_keys";
ALTER INDEX "idx_byok_org_provider" RENAME TO "idx_org_keys_org_provider";
