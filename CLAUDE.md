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
