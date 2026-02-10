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
