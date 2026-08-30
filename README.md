# Key Service

API key and BYOK (Bring Your Own Key) management microservice. Handles authentication key generation, validation, and secure storage of external API keys.

## Features

- **API Key Management**: Generate, validate, and revoke API keys for client authentication
- **BYOK Key Storage**: Securely store and retrieve external API keys (Apollo, Anthropic, etc.)
- **Multi-credential providers**: `featured` (Featured.com Premium) stores `{username, password}` as a single encrypted JSON blob
- **AES-256-GCM Encryption**: All sensitive keys encrypted at rest
- **Auto-migrations**: Database schema automatically applied on startup
- **Service-to-Service Auth**: Internal routes protected by KEY_SERVICE_API_KEY

## Provider value shapes

Most providers store a single string secret. The `apiKey` request field also accepts an
object for providers that need multi-field credentials:

```jsonc
// Single-string providers (anthropic, openai, gemini, …)
{ "provider": "anthropic", "apiKey": "sk-ant-..." }

// featured — Featured.com Premium API uses basic auth
{ "provider": "featured", "apiKey": { "username": "press@x.com", "password": "..." } }
```

Decrypt endpoints return the value in the original shape — string for string providers,
object for `featured`.

## Tech Stack

- **Runtime**: Node.js 20, TypeScript, ESM
- **Framework**: Express 4
- **Database**: PostgreSQL with Drizzle ORM
- **Auth**: Clerk (for org membership lookup)
- **Monitoring**: Sentry

## Environment Variables

```bash
# Required
KEY_SERVICE_DATABASE_URL=postgres://...  # PostgreSQL connection string
ENCRYPTION_KEY=<64-char-hex>             # 32-byte hex key for AES-256-GCM
CLERK_SECRET_KEY=sk_...                  # Clerk backend API key
KEY_SERVICE_API_KEY=<secret>             # Service-to-service auth key

# Optional
SENTRY_DSN=https://...                   # Sentry error tracking
```

## Development

```bash
# Install dependencies
pnpm install

# Start development server
pnpm dev

# Run tests
pnpm test

# Build for production
pnpm build

# Start production server
pnpm start
```

## Database

```bash
# Generate migration after schema change
pnpm db:generate

# Apply migrations manually (auto-applied on startup)
pnpm db:migrate

# Open Drizzle Studio GUI
pnpm db:studio
```

## Tests in CI

`.github/workflows/test.yml` runs the suite against a `postgres:16` service
container started for that run and destroyed with the job — never a shared,
staging or production database. The container starts empty; the schema under
test is built from `src/db/schema.ts` via `drizzle-kit push`, and the migration
journal is separately replayed from nothing into a second database so a
migration that only works against an already-populated one fails in CI rather
than in the boot migrator.

## API Endpoints

### Health (Public)
- `GET /health` — Health check

### Validation (API Key Auth Required)
- `GET /validate` — Validate API key, returns org info
- `GET /validate/keys/:provider` — Get decrypted BYOK key

### Internal (Service Key Required via `X-Service-Key` header)
- `GET /internal/api-keys` — List API keys
- `POST /internal/api-keys` — Create API key
- `DELETE /internal/api-keys/:id` — Delete API key
- `GET /internal/keys` — List BYOK keys (masked)
- `POST /internal/keys` — Upsert BYOK key
- `DELETE /internal/keys/:provider` — Delete BYOK key
- `GET /internal/keys/:provider/decrypt` — Decrypt BYOK key

## Docker

```bash
# Build image
docker build -t key-service .

# Run container
docker run -p 3001:3001 \
  -e KEY_SERVICE_DATABASE_URL=... \
  -e ENCRYPTION_KEY=... \
  -e CLERK_SECRET_KEY=... \
  -e KEY_SERVICE_API_KEY=... \
  key-service
```

## License

Private
