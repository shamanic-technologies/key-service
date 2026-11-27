# Project: key-service

API key and BYOK (Bring Your Own Key) management microservice. Handles key generation, validation, encryption, and secure storage.

## Commands

- `npm test` — run tests (vitest)
- `npm run build` — compile TypeScript + generate OpenAPI spec
- `npm run dev` — local dev server (tsx watch)
- `npm run generate:openapi` — regenerate openapi.json from Zod schemas
- `npm run db:generate` — generate Drizzle migration after schema change
- `npm run db:migrate` — apply migrations manually
- `npm run db:studio` — open Drizzle Studio GUI

## Architecture

- `src/schemas.ts` — Zod schemas + OpenAPI registry (source of truth for validation + docs)
- `src/routes/health.ts` — Health check endpoint (public)
- `src/routes/validate.ts` — API key validation + BYOK key retrieval (bearer auth)
- `src/routes/internal.ts` — Internal CRUD for API keys and BYOK keys (service key auth)
- `src/routes/brand-keys.ts` — Brand-scoped third-party credentials (`/keys/brands/*`). A second GRAIN beside the org-wide keys in `routes/keys.ts`, for an agency org whose brands are separate end clients with their own sub-account at the same provider. Mounted BEFORE `/keys` in `src/index.ts` so the org-grain `/:provider` routes are reached exactly as before. The two grains never read each other: a brand credential that is not stored is a 404, never the org-wide one and never another brand's.
- `src/routes/internal-keys.ts` — `/internal/keys/by-org/:orgId/*`: org-keyed routes with NO user, for machine callers (webhooks, pollers, teardown). `GET …/:provider/source` = the org's key-source preference, same body as `/keys/:provider/source`. A machine caller never fakes an `x-user-id` to reach `/keys/*`; it calls here.
- `src/routes/transfer-brand.ts` — `POST /internal/transfer-brand`, the fleet brand-transfer contract brand-service discovers via api-registry. Moves a brand's `brand_keys` rows from source org to target org (and to `targetBrandId` when given); org-wide keys stay with the org. On collision the target's existing credential wins and the source row is removed, so the source org holds none of the brand's credentials afterwards. Idempotent; returns `{updatedTables:[{tableName,count}]}` and never key material.
- `src/routes/user-api-keys.ts` — `/internal/user-api-keys/by-user/:userId` (GET list, DELETE `/:id`): a user's own `distrib.usr_*` keys across EVERY org, keyed on the user UUID, no `x-org-id`. A user API key belongs to its user, not to the org active when it was minted (owner 2026-10-01). Another user's key is a 404 on DELETE. The org-scoped `/api-keys` routes stay for creation and the session key; never list keys for a customer through them (they return every member's keys in the org).
- `src/lib/audit.ts` + `src/lib/security-alerts.ts` + `src/routes/security.ts` — SECURITY-ALERTS-1128 (2026-11-20 hack: a leaked service key created platform key `probe26210` and decrypted ~57 platform keys, nothing alerted). Every decrypt/create/update/delete of a platform, org or brand key, and every wrong-service-key request, writes ONE row in `secret_audit_events` BEFORE the response (a decrypt whose row cannot be written is a 500, never a key without its trace). Append-only by DB trigger (no UPDATE; DELETE only past 90 days, pruned hourly). Never a key value, and the query string is dropped (`/validate/keys` carries a user key there). Four checks run after each row; a hit opens or joins an incident (`security_incidents`, same kind+subject within 1 h = same incident) mailed to staff ONCE via transactional-email-service `POST /platform-staff-alert` `security_alert` (eventId `key-service:<kind>:<id>`; undelivered alerts are resent every minute under the same eventId): `key_write` (any real key change; a boot registration re-sending the same value writes nothing), `unknown_caller_decrypt` (caller service absent from `known_callers` or last seen > 30 days; the seed in migration 0011 deliberately leaves out the attacker and one-off staff names), `provider_sweep` (> 20 distinct providers per caller service or > 40 per source address in 10 min), `auth_failure_burst` (>= 5 wrong-key requests from one source in 10 min). Thresholds live as constants with their prod baseline. `GET /internal/security/daily` = the Monitoring series. Never log any character of a key (the old `auth REJECTED` line printed 4 of the expected key).
- `src/middleware/auth.ts` — Auth middleware (bearer token + service key)
- `src/lib/crypto.ts` — AES-256-GCM encryption/decryption
- `src/lib/api-key.ts` — API key generation and hashing
- `src/db/schema.ts` — Drizzle ORM table definitions (PostgreSQL)
- `src/db/index.ts` — Database connection
- `src/instrument.ts` — Sentry instrumentation
- `src/index.ts` — Express app setup and server entry point
- `tests/` — Test files (`*.test.ts`)
- `openapi.json` — Auto-generated from Zod schemas, do NOT edit manually

## CI

Tests run against a `postgres:16` service container started for that run and
destroyed with the job (`.github/workflows/test.yml`) — never a shared, staging
or production database. Two invariants:

- **The database starts EMPTY.** The schema under test is built from
  `src/db/schema.ts` by `drizzle-kit push`, so any statement that only works
  against an already-populated database fails here. The migration journal is
  separately replayed from nothing into a second database, because
  `src/index.ts` migrates before `listen()` on a fresh environment.
- **`drizzle-kit push` exits 0 on a failed statement.** It prints the error,
  abandons every statement after it, and returns success — which on an empty
  database means serving the suite a half-built schema. The push step greps its
  own output and fails the job on any error. This repo's drizzle-kit prints
  `PostgresError:` / `severity: 'ERROR'`, not `error:` — verify the pattern
  against real output before changing it.
