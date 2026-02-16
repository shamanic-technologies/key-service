import { z } from "zod";
import {
  OpenAPIRegistry,
  extendZodWithOpenApi,
} from "@asteasolutions/zod-to-openapi";

extendZodWithOpenApi(z);
export const registry = new OpenAPIRegistry();

// ==================== Shared ====================

const ErrorResponseSchema = z
  .object({
    error: z.string(),
  })
  .openapi("ErrorResponse");

// ==================== Health ====================

const HealthResponseSchema = z
  .object({
    status: z.string(),
    timestamp: z.string(),
    service: z.string(),
  })
  .openapi("HealthResponse");

registry.registerPath({
  method: "get",
  path: "/health",
  summary: "Health check",
  responses: {
    200: {
      description: "Service is healthy",
      content: { "application/json": { schema: HealthResponseSchema } },
    },
  },
});

// ==================== Validate ====================

const ValidateResponseSchema = z
  .object({
    valid: z.boolean(),
    orgId: z.string().uuid(),
    clerkOrgId: z.string(),
    clerkUserId: z.string().nullable(),
    configuredProviders: z.array(z.string()),
  })
  .openapi("ValidateResponse");

registry.registerPath({
  method: "get",
  path: "/validate",
  summary: "Validate API key and return org info",
  security: [{ bearerAuth: [] }],
  responses: {
    200: {
      description: "API key is valid",
      content: { "application/json": { schema: ValidateResponseSchema } },
    },
    401: { description: "Unauthorized" },
    404: { description: "Organization not found" },
  },
});

const ValidateKeyResponseSchema = z
  .object({
    provider: z.string(),
    key: z.string(),
  })
  .openapi("ValidateKeyResponse");

registry.registerPath({
  method: "get",
  path: "/validate/keys/{provider}",
  summary: "Get decrypted BYOK key for a provider",
  security: [{ bearerAuth: [] }],
  request: {
    params: z.object({
      provider: z.string(),
    }),
  },
  responses: {
    200: {
      description: "Decrypted key",
      content: { "application/json": { schema: ValidateKeyResponseSchema } },
    },
    401: { description: "Unauthorized" },
    404: { description: "Key not configured" },
  },
});

// ==================== Internal: API Keys ====================

const ClerkOrgIdQuerySchema = z
  .object({
    clerkOrgId: z.string().min(1),
  })
  .openapi("ClerkOrgIdQuery");

const ApiKeyItemSchema = z
  .object({
    id: z.string().uuid(),
    keyPrefix: z.string(),
    name: z.string().nullable(),
    createdAt: z.coerce.date(),
    lastUsedAt: z.coerce.date().nullable(),
  })
  .openapi("ApiKeyItem");

const ListApiKeysResponseSchema = z
  .object({
    keys: z.array(ApiKeyItemSchema),
  })
  .openapi("ListApiKeysResponse");

registry.registerPath({
  method: "get",
  path: "/internal/api-keys",
  summary: "List API keys for an org",
  security: [{ serviceKeyAuth: [] }],
  request: {
    query: ClerkOrgIdQuerySchema,
  },
  responses: {
    200: {
      description: "List of API keys",
      content: { "application/json": { schema: ListApiKeysResponseSchema } },
    },
    400: { description: "Missing clerkOrgId" },
  },
});

export const CreateApiKeyRequestSchema = z
  .object({
    clerkOrgId: z.string().min(1),
    name: z.string().optional(),
  })
  .openapi("CreateApiKeyRequest");

const CreateApiKeyResponseSchema = z
  .object({
    id: z.string().uuid(),
    key: z.string(),
    keyPrefix: z.string(),
    name: z.string().nullable(),
    message: z.string(),
  })
  .openapi("CreateApiKeyResponse");

registry.registerPath({
  method: "post",
  path: "/internal/api-keys",
  summary: "Create a new API key",
  security: [{ serviceKeyAuth: [] }],
  request: {
    body: {
      content: { "application/json": { schema: CreateApiKeyRequestSchema } },
    },
  },
  responses: {
    200: {
      description: "API key created",
      content: { "application/json": { schema: CreateApiKeyResponseSchema } },
    },
    400: { description: "Invalid request" },
  },
});

export const DeleteApiKeyRequestSchema = z
  .object({
    clerkOrgId: z.string().min(1),
  })
  .openapi("DeleteApiKeyRequest");

const MessageResponseSchema = z
  .object({
    message: z.string(),
  })
  .openapi("MessageResponse");

registry.registerPath({
  method: "delete",
  path: "/internal/api-keys/{id}",
  summary: "Delete an API key",
  security: [{ serviceKeyAuth: [] }],
  request: {
    params: z.object({ id: z.string().uuid() }),
    body: {
      content: { "application/json": { schema: DeleteApiKeyRequestSchema } },
    },
  },
  responses: {
    200: {
      description: "API key deleted",
      content: { "application/json": { schema: MessageResponseSchema } },
    },
    400: { description: "Missing clerkOrgId" },
    404: { description: "API key not found" },
  },
});

export const SessionApiKeyRequestSchema = z
  .object({
    clerkOrgId: z.string().min(1),
  })
  .openapi("SessionApiKeyRequest");

const SessionApiKeyResponseSchema = z
  .object({
    id: z.string().uuid(),
    key: z.string(),
    keyPrefix: z.string(),
    name: z.string().nullable(),
  })
  .openapi("SessionApiKeyResponse");

registry.registerPath({
  method: "post",
  path: "/internal/api-keys/session",
  summary: "Get or create a default API key for the org",
  security: [{ serviceKeyAuth: [] }],
  request: {
    body: {
      content: {
        "application/json": { schema: SessionApiKeyRequestSchema },
      },
    },
  },
  responses: {
    200: {
      description: "Session API key",
      content: { "application/json": { schema: SessionApiKeyResponseSchema } },
    },
    400: { description: "Missing clerkOrgId" },
  },
});

// ==================== Internal: BYOK Keys ====================

const ByokKeyItemSchema = z
  .object({
    provider: z.string(),
    maskedKey: z.string(),
    createdAt: z.coerce.date(),
    updatedAt: z.coerce.date(),
  })
  .openapi("ByokKeyItem");

const ListByokKeysResponseSchema = z
  .object({
    keys: z.array(ByokKeyItemSchema),
  })
  .openapi("ListByokKeysResponse");

registry.registerPath({
  method: "get",
  path: "/internal/keys",
  summary: "List BYOK keys for an org",
  security: [{ serviceKeyAuth: [] }],
  request: {
    query: ClerkOrgIdQuerySchema,
  },
  responses: {
    200: {
      description: "List of BYOK keys",
      content: { "application/json": { schema: ListByokKeysResponseSchema } },
    },
    400: { description: "Missing clerkOrgId" },
  },
});

const VALID_PROVIDERS = ["apollo", "anthropic"] as const;

export const CreateByokKeyRequestSchema = z
  .object({
    clerkOrgId: z.string().min(1),
    provider: z.enum(VALID_PROVIDERS),
    apiKey: z.string().min(1),
  })
  .openapi("CreateByokKeyRequest");

const CreateByokKeyResponseSchema = z
  .object({
    provider: z.string(),
    maskedKey: z.string(),
    message: z.string(),
  })
  .openapi("CreateByokKeyResponse");

registry.registerPath({
  method: "post",
  path: "/internal/keys",
  summary: "Add or update a BYOK key",
  security: [{ serviceKeyAuth: [] }],
  request: {
    body: {
      content: {
        "application/json": { schema: CreateByokKeyRequestSchema },
      },
    },
  },
  responses: {
    200: {
      description: "BYOK key saved",
      content: {
        "application/json": { schema: CreateByokKeyResponseSchema },
      },
    },
    400: { description: "Invalid request" },
  },
});

export const DeleteByokKeyQuerySchema = z
  .object({
    clerkOrgId: z.string().min(1),
  })
  .openapi("DeleteByokKeyQuery");

const DeleteByokKeyResponseSchema = z
  .object({
    provider: z.string(),
    message: z.string(),
  })
  .openapi("DeleteByokKeyResponse");

registry.registerPath({
  method: "delete",
  path: "/internal/keys/{provider}",
  summary: "Delete a BYOK key",
  security: [{ serviceKeyAuth: [] }],
  request: {
    params: z.object({
      provider: z.enum(VALID_PROVIDERS),
    }),
    query: DeleteByokKeyQuerySchema,
  },
  responses: {
    200: {
      description: "BYOK key deleted",
      content: {
        "application/json": { schema: DeleteByokKeyResponseSchema },
      },
    },
    400: { description: "Invalid request" },
  },
});

const DecryptByokKeyResponseSchema = z
  .object({
    provider: z.string(),
    key: z.string(),
  })
  .openapi("DecryptByokKeyResponse");

registry.registerPath({
  method: "get",
  path: "/internal/keys/{provider}/decrypt",
  summary: "Get decrypted BYOK key (internal service use)",
  security: [{ serviceKeyAuth: [] }],
  request: {
    params: z.object({ provider: z.string() }),
    query: ClerkOrgIdQuerySchema,
  },
  responses: {
    200: {
      description: "Decrypted key",
      content: {
        "application/json": { schema: DecryptByokKeyResponseSchema },
      },
    },
    400: { description: "Missing clerkOrgId" },
    404: { description: "Key not configured" },
  },
});

// ==================== Internal: App Keys ====================

const AppIdQuerySchema = z
  .object({
    appId: z.string().min(1),
  })
  .openapi("AppIdQuery");

const AppKeyItemSchema = z
  .object({
    provider: z.string(),
    maskedKey: z.string(),
    createdAt: z.coerce.date(),
    updatedAt: z.coerce.date(),
  })
  .openapi("AppKeyItem");

const ListAppKeysResponseSchema = z
  .object({
    keys: z.array(AppKeyItemSchema),
  })
  .openapi("ListAppKeysResponse");

registry.registerPath({
  method: "get",
  path: "/internal/app-keys",
  summary: "List app keys for an app",
  security: [{ serviceKeyAuth: [] }],
  request: {
    query: AppIdQuerySchema,
  },
  responses: {
    200: {
      description: "List of app keys",
      content: { "application/json": { schema: ListAppKeysResponseSchema } },
    },
    400: { description: "Missing appId" },
  },
});

export const CreateAppKeyRequestSchema = z
  .object({
    appId: z.string().min(1),
    provider: z.string().min(1),
    apiKey: z.string().min(1),
  })
  .openapi("CreateAppKeyRequest");

const CreateAppKeyResponseSchema = z
  .object({
    provider: z.string(),
    maskedKey: z.string(),
    message: z.string(),
  })
  .openapi("CreateAppKeyResponse");

registry.registerPath({
  method: "post",
  path: "/internal/app-keys",
  summary: "Add or update an app key",
  security: [{ serviceKeyAuth: [] }],
  request: {
    body: {
      content: {
        "application/json": { schema: CreateAppKeyRequestSchema },
      },
    },
  },
  responses: {
    200: {
      description: "App key saved",
      content: {
        "application/json": { schema: CreateAppKeyResponseSchema },
      },
    },
    400: { description: "Invalid request" },
  },
});

export const DeleteAppKeyQuerySchema = z
  .object({
    appId: z.string().min(1),
  })
  .openapi("DeleteAppKeyQuery");

const DeleteAppKeyResponseSchema = z
  .object({
    provider: z.string(),
    message: z.string(),
  })
  .openapi("DeleteAppKeyResponse");

registry.registerPath({
  method: "delete",
  path: "/internal/app-keys/{provider}",
  summary: "Delete an app key",
  security: [{ serviceKeyAuth: [] }],
  request: {
    params: z.object({
      provider: z.string(),
    }),
    query: DeleteAppKeyQuerySchema,
  },
  responses: {
    200: {
      description: "App key deleted",
      content: {
        "application/json": { schema: DeleteAppKeyResponseSchema },
      },
    },
    400: { description: "Invalid request" },
  },
});

const DecryptAppKeyResponseSchema = z
  .object({
    provider: z.string(),
    key: z.string(),
  })
  .openapi("DecryptAppKeyResponse");

registry.registerPath({
  method: "get",
  path: "/internal/app-keys/{provider}/decrypt",
  summary: "Get decrypted app key (internal service use)",
  security: [{ serviceKeyAuth: [] }],
  request: {
    params: z.object({ provider: z.string() }),
    query: AppIdQuerySchema,
  },
  responses: {
    200: {
      description: "Decrypted key",
      content: {
        "application/json": { schema: DecryptAppKeyResponseSchema },
      },
    },
    400: { description: "Missing appId" },
    404: { description: "Key not configured" },
  },
});

// ==================== Security schemes ====================

registry.registerComponent("securitySchemes", "bearerAuth", {
  type: "http",
  scheme: "bearer",
  description: "API key (mcpf_*) in Bearer token",
});

registry.registerComponent("securitySchemes", "serviceKeyAuth", {
  type: "apiKey",
  in: "header",
  name: "x-api-key",
  description: "Service-to-service key (KEY_SERVICE_API_KEY)",
});
